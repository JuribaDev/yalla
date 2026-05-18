package dokploy

// ServiceType identifies which kind of Dokploy service a Service is. It mirrors
// Dokploy's own notion of a service: a long-running application, a Docker
// Compose stack, or a managed database.
type ServiceType string

const (
	// ServiceApplication is a long-running application service.
	ServiceApplication ServiceType = "application"
	// ServiceCompose is a Docker Compose stack service.
	ServiceCompose ServiceType = "compose"
	// ServiceDatabase is a managed database service; it requires an Engine.
	ServiceDatabase ServiceType = "database"
)

// Valid reports whether t is one of the recognised service types.
func (t ServiceType) Valid() bool {
	switch t {
	case ServiceApplication, ServiceCompose, ServiceDatabase:
		return true
	default:
		return false
	}
}

// Deployment lifecycle states, mirroring Dokploy's own status vocabulary.
const (
	// DeploymentPending is a deployment that has been accepted but not started.
	DeploymentPending = "pending"
	// DeploymentRunning is a deployment that is in progress.
	DeploymentRunning = "running"
	// DeploymentSucceeded is a deployment that completed successfully.
	DeploymentSucceeded = "succeeded"
	// DeploymentFailed is a deployment that finished with an error.
	DeploymentFailed = "failed"
)

// Organization is the top of the Dokploy hierarchy.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Project belongs to exactly one Organization.
type Project struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
}

// Environment belongs to exactly one Project.
type Environment struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
}

// Service is an application, compose stack, or database under an Environment.
type Service struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	// Engine is set only for database services (for example "postgres").
	Engine string `json:"engine,omitempty"`
	// Status is the service's runtime status.
	Status string `json:"status"`
}

// Domain is a hostname bound to a Service.
type Domain struct {
	ID        string `json:"id"`
	ServiceID string `json:"service_id"`
	Host      string `json:"host"`
	HTTPS     bool   `json:"https"`
}

// Deployment is one provisioning run against a Service.
type Deployment struct {
	ID        string `json:"id"`
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
}

// Succeeded reports whether the deployment finished successfully.
func (d Deployment) Succeeded() bool { return d.Status == DeploymentSucceeded }

// DeploymentLogs is the captured log output of one Deployment.
type DeploymentLogs struct {
	DeploymentID string   `json:"deployment_id"`
	Lines        []string `json:"lines"`
}

// ServiceStatus is the runtime status of a Service.
type ServiceStatus struct {
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
}

// EnsureOrganizationInput describes the desired state of a Dokploy
// organization. When ExistingID is set the organization is fetched and
// verified instead of created, so the call is idempotent against Yalla's
// source-of-truth state: a caller that already recorded a Dokploy ID never
// risks creating a duplicate.
type EnsureOrganizationInput struct {
	// ExistingID, when non-empty, is the Dokploy organization ID to fetch and
	// verify rather than create.
	ExistingID string
	// Name is the organization name; required when ExistingID is empty.
	Name string
}

// EnsureProjectInput describes the desired state of a Dokploy project.
type EnsureProjectInput struct {
	// ExistingID, when non-empty, is the Dokploy project ID to fetch and verify.
	ExistingID string
	// OrganizationID is the parent organization; required when creating.
	OrganizationID string
	// Name is the project name; required when creating.
	Name string
}

// EnsureEnvironmentInput describes the desired state of a Dokploy environment.
type EnsureEnvironmentInput struct {
	// ExistingID, when non-empty, is the Dokploy environment ID to fetch.
	ExistingID string
	// ProjectID is the parent project; required when creating.
	ProjectID string
	// Name is the environment name; required when creating.
	Name string
}

// EnsureServiceInput describes the desired state of a Dokploy service.
type EnsureServiceInput struct {
	// ExistingID, when non-empty, is the Dokploy service ID to fetch. Type must
	// still be set so the client knows which Dokploy resource path to read.
	ExistingID string
	// EnvironmentID is the parent environment; required when creating.
	EnvironmentID string
	// Name is the service name; required when creating.
	Name string
	// Type selects the kind of service; always required.
	Type ServiceType
	// Engine is the database engine; required when Type is ServiceDatabase and
	// ignored otherwise.
	Engine string
}

// EnsureDomainInput describes the desired state of a Dokploy domain.
type EnsureDomainInput struct {
	// ExistingID, when non-empty, is the Dokploy domain ID to fetch.
	ExistingID string
	// ServiceID is the service the domain is bound to; required when creating.
	ServiceID string
	// Host is the hostname; required when creating.
	Host string
	// HTTPS reports whether the domain should terminate TLS.
	HTTPS bool
}

// DeployServiceInput names the service to deploy.
type DeployServiceInput struct {
	// ServiceID is the service to deploy; required.
	ServiceID string
}

// RestartServiceInput names the service to restart.
type RestartServiceInput struct {
	// ServiceID is the service to restart; required.
	ServiceID string
}

// StopServiceInput names the service to stop.
type StopServiceInput struct {
	// ServiceID is the service to stop; required.
	ServiceID string
}

// RemoveServiceInput names the service to remove.
type RemoveServiceInput struct {
	// ServiceID is the service to remove; required.
	ServiceID string
}
