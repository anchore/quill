package notarize

import "time"

type submissionRequest struct {
	Sha256         string `json:"sha256"`
	SubmissionName string `json:"submissionName"`
}

type submissionResponseDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type submissionResponse struct {
	Data submissionResponseData `json:"data"`
}

type submissionResponseData struct {
	submissionResponseDescriptor
	Attributes submissionResponseAttributes `json:"attributes"`
}

type submissionResponseAttributes struct {
	AwsAccessKeyID     string `json:"awsAccessKeyId"`
	AwsSecretAccessKey string `json:"awsSecretAccessKey"`
	AwsSessionToken    string `json:"awsSessionToken"`
	Bucket             string `json:"bucket"`
	Object             string `json:"object"`
}

type submissionStatusResponse struct {
	Data submissionStatusResponseData `json:"data"`
}

type submissionStatusResponseData struct {
	submissionResponseDescriptor
	Attributes submissionStatusResponseAttributes `json:"attributes"`
}

type submissionStatusResponseAttributes struct {
	Status      string    `json:"status"`
	Name        string    `json:"name"`
	CreatedDate time.Time `json:"createdDate"`
}

type submissionLogsResponse struct {
	Data submissionLogsResponseData `json:"data"`
}

type submissionLogsResponseData struct {
	submissionResponseDescriptor
	Attributes submissionLogsResponseAttributes `json:"attributes"`
}

type submissionLogsResponseAttributes struct {
	DeveloperLogURL string `json:"developerLogUrl"`
}
