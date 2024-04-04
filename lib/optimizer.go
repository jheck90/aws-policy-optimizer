// optimizer/optimizer.go

package optimizer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"log"
	"net/url"

	"github.com/gigawattio/awsarn"
	"github.com/flosell/iam-policy-json-to-terraform/converter"
	"github.com/micahhausler/aws-iam-policy/policy"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/evanphx/json-patch"
)

// GenerateOptimizedPolicyOptions represents the options for generating an optimized IAM policy
type GenerateOptimizedPolicyOptions struct {
	Database           string
	Table              string
	QueryResultsBucket string
	QueryResultsPrefix string
	AthenaWorkgroup    string
	IAMRole            string
	AccountID          string
	Region             string
	OutputFormat       string
	AnalysisPeriod     int
	Diff       			   bool
}

// DiffResult represents the result of a policy diff
type DiffResult struct {
	DiffExists bool
}

// GenerateOptimizedPolicy generates an optimized IAM policy based on the provided options
func GenerateOptimizedPolicy(options GenerateOptimizedPolicyOptions) (string, error) {
	start := time.Now().AddDate(0, 0, options.AnalysisPeriod*-1)

	sql := fmt.Sprintf(`
	SELECT DISTINCT
		useridentity.sessionContext.sessionIssuer.arn as useridentity,
		CONCAT(SPLIT_PART(eventsource, '.', 1),':',eventname) as permission,
		resource.arn as resource
	FROM "%s"."%s"
	CROSS JOIN UNNEST(resources) AS t(resource)
	WHERE day > '%s'
	AND regexp_like(useridentity.arn, '%s')
	AND account_id = '%s'
	AND region = '%s'
	AND NULLIF(errorcode, '') IS NULL
	`, options.Database, options.Table, start.Format("2006/01/02"), options.IAMRole, options.AccountID, options.Region)

	var usageHistory []UsageHistoryRecord
	err := QueryAthena(sql, options.Database, options.QueryResultsBucket, options.QueryResultsPrefix, options.AthenaWorkgroup, &usageHistory)
	if err != nil {
		return "", err
	}

	// generate the permissions map map[identity]map[permission]resource
	var permissionMap = make(map[string]map[string][]string)
	for _, record := range usageHistory {
		if _, ok := permissionMap[record.UserIdenityArn]; ok {
			permissionMap[record.UserIdenityArn][record.Permission] = append(permissionMap[record.UserIdenityArn][record.Permission], record.ResourceArn)

			if _, ok := permissionMap[record.UserIdenityArn][record.Permission]; ok {
				permissionMap[record.UserIdenityArn][record.Permission] = append(permissionMap[record.UserIdenityArn][record.Permission], record.ResourceArn)
			} else {
				permissionMap[record.UserIdenityArn][record.Permission] = []string{record.ResourceArn}
			}

		} else {
			permissionMap[record.UserIdenityArn] = make(map[string][]string)
			permissionMap[record.UserIdenityArn][record.Permission] = []string{record.ResourceArn}
		}
	}

	// Deduplicate the permissions -> Resource map
	// Build the final IAM Policy
	var statements = []policy.Statement{}
	for identity, permissionSet := range permissionMap {
		for action, resources := range permissionSet {
			consolidatedResources, err := consolidateARNs(resources)
			if err != nil {
				return "", err
			}
			actions := []string{action}

			// deduplicate policies
			for dupeAction, dupeResources := range permissionSet {
				dupeConsolidatedResources, err := consolidateARNs(dupeResources)
				if err != nil {
					return "", err
				}
				if dupeAction == action {
					continue
				}
				if reflect.DeepEqual(consolidatedResources, dupeConsolidatedResources) {
					actions = append(actions, dupeAction)
					delete(permissionMap[identity], dupeAction)
				}
			}

			statements = append(statements, policy.Statement{
				Effect:   policy.EffectAllow,
				Action:   policy.NewStringOrSlice(false, actions...),
				Resource: policy.NewStringOrSlice(false, consolidatedResources...),
			},
			)
		}
	}

	// Query current policy
	currentPolicyJSON, err := QueryCurrentPolicy(options)
	if err != nil {
		return "", err
	}

	// Generate new policy
	p := policy.Policy{
		Version:    policy.VersionLatest,
		Id:         "GenIAMPolicy", // TODO: better ID
		Statements: policy.NewStatementOrSlice(statements...),
	}

	newPolicyJSON, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	// Check for exact match
	exactMatch := CheckForExactMatch(currentPolicyJSON, newPolicyJSON)
	if exactMatch {
		return "Found exact match", nil
	}

	// Diff policies if enabled
	if options.Diff {
		diffResult, err := DiffPolicies(currentPolicyJSON, newPolicyJSON)
		if err != nil {
			return "", err
		}

		if diffResult.DiffExists {
			// Handle diff result
		}
	}

	out, _ := json.MarshalIndent(p, "", "\t")

	if options.OutputFormat == "hcl" {
		return converter.Convert("GenIAMPolicy", out)
	} else {
		return string(out), nil
	}
}

func consolidateARNs(arns []string) ([]string, error) {
	var arnMap = make(map[string][]string)
	for _, arn := range arns {
		if arn == "" {
			continue
		}
		components, err := awsarn.Parse(arn)
		if err != nil {
			return nil, err
		}
		resource := components.Resource
		components.Resource = ""
		if val, ok := arnMap[components.String()]; ok {
			arnMap[components.String()] = append(val, resource)
		} else {
			arnMap[components.String()] = []string{resource}
		}
	}

	var ss []string
	for arn, resources := range arnMap {
		globbedArn, _ := awsarn.Parse(arn)
		globbedArn.Resource = generateGlobPattern(resources)
		ss = append(ss, globbedArn.String())
	}

	return ss, nil
}

// DiffPolicies diffs the current policy with the new policy
func DiffPolicies(currentPolicyJSON, newPolicyJSON []byte) (DiffResult, error) {
	log.Println("DiffPolicies: Starting diff operation")
	defer log.Println("DiffPolicies: Diff operation completed")

	log.Printf("DiffPolicies: Current policy JSON: %s\n", string(currentPolicyJSON))
	log.Printf("DiffPolicies: New policy JSON: %s\n", string(newPolicyJSON))

	patch, err := jsonpatch.CreateMergePatch(currentPolicyJSON, newPolicyJSON)
	if err != nil {
			log.Printf("DiffPolicies: Error creating merge patch: %v\n", err)
			return DiffResult{}, err
	}

	// If patch is empty, policies are equal
	diffExists := len(patch) > 0

	log.Printf("DiffPolicies: Diff exists: %t\n", diffExists)
	return DiffResult{DiffExists: diffExists}, nil
}

// CheckForExactMatch checks if the generated policy matches the existing policy exactly
func CheckForExactMatch(existingPolicyJSON, newPolicyJSON []byte) bool {
	log.Println("CheckForExactMatch: Starting exact match check")
	defer log.Println("CheckForExactMatch: Exact match check completed")

	return reflect.DeepEqual(existingPolicyJSON, newPolicyJSON)
}

func QueryCurrentPolicy(options GenerateOptimizedPolicyOptions) ([]byte, error) {
	// First, get the policy ARN
	policyARN, err := getPolicyARN(options)
	if err != nil {
			return nil, err
	}

	// Get the default version ID of the policy
	versionID, err := getPolicyDefaultVersionID(policyARN)
	if err != nil {
			return nil, err
	}

	// Now, query the policy JSON using the obtained policy ARN and version ID
	existingPolicyJSON, err := getPolicyJSON(policyARN, versionID)
	if err != nil {
			return nil, err
	}

	// Decode URL-encoded data, if needed
	existingPolicyString, err := url.QueryUnescape(string(existingPolicyJSON))
	if err != nil {
			return nil, err
	}

	// Convert the decoded string back to a byte slice
	existingPolicyJSON = []byte(existingPolicyString)

	return existingPolicyJSON, nil
}


func getPolicyARN(options GenerateOptimizedPolicyOptions) (string, error) {
	log.Println("getPolicyARN: Generating policy ARN")
	defer log.Println("getPolicyARN: Policy ARN generated")

	// Assuming roleName is in the format provided in the question
	policyARN := fmt.Sprintf("arn:aws:iam::%s:policy/%s", options.AccountID, options.IAMRole)
	return policyARN, nil
}

func getPolicyDefaultVersionID(policyARN string) (string, error) {
	log.Println("getPolicyDefaultVersionID: Retrieving default policy version ID")
	defer log.Println("getPolicyDefaultVersionID: Default policy version ID retrieved")

	// Create an AWS session
	sess := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
	}))

	// Create an IAM client
	svc := iam.New(sess)

	// Input parameters for GetPolicyVersion API call
	input := &iam.GetPolicyInput{
			PolicyArn: aws.String(policyARN),
	}

	// Execute the GetPolicyVersion API call
	resp, err := svc.GetPolicy(input)
	if err != nil {
			log.Printf("getPolicyDefaultVersionID: Error retrieving policy: %v\n", err)
			return "", err
	}

	// Extract the default version ID from the response
	versionID := aws.StringValue(resp.Policy.DefaultVersionId)

	return versionID, nil
}

func getPolicyJSON(policyARN, versionID string) ([]byte, error) {
	log.Println("getPolicyJSON: Retrieving policy JSON document")
	defer log.Println("getPolicyJSON: Policy JSON document retrieved")

	// Create an AWS session
	sess := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
	}))

	// Create an IAM client
	svc := iam.New(sess)

	// Input parameters for GetPolicyVersion API call
	input := &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(policyARN),
			VersionId: aws.String(versionID),
	}

	// Execute the GetPolicyVersion API call
	resp, err := svc.GetPolicyVersion(input)
	if err != nil {
			log.Printf("getPolicyJSON: Error retrieving policy version: %v\n", err)
			return nil, err
	}

	// Extract the policy JSON document from the response
	policyDocument := aws.StringValue(resp.PolicyVersion.Document)

	return []byte(policyDocument), nil
}

func generateGlobPattern(ss []string) string {
	if len(ss) == 0 {
		return ""
	}

	parts := strings.Split(ss[0], "/")
	for i := 1; i < len(parts); i++ {
		for _, s := range ss {
			if !strings.HasPrefix(s, strings.Join(parts[:i+1], "/")) {
				return strings.Join(parts[:i], "/") + "/*"
			}
		}
	}

	return strings.Join(parts, "/")
}

// UsageHistoryRecord represents a record in the usage history
type UsageHistoryRecord struct {
	UserIdenityArn string `csv:"useridentity"`
	Permission     string `csv:"permission"`
	ResourceArn    string `csv:"resource"`
}