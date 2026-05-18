package dokploy

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// encodeBody marshals a request body to JSON.
func encodeBody(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode dokploy request body: %w", err)
	}
	return b, nil
}

// decodeBody unmarshals a JSON response body into dst.
func decodeBody(payload []byte, dst any) error {
	return json.Unmarshal(payload, dst)
}

// EnsureOrganization makes a Dokploy organization exist. When in.ExistingID is
// set the organization is fetched and verified; otherwise it is created.
func (c *Client) EnsureOrganization(ctx context.Context, in EnsureOrganizationInput) (Organization, error) {
	if id := strings.TrimSpace(in.ExistingID); id != "" {
		var org Organization
		if err := c.get(ctx, "/api/organizations/"+url.PathEscape(id), &org); err != nil {
			return Organization{}, err
		}
		return org, nil
	}
	if v := requireFields(field{"name", in.Name}); v != nil {
		return Organization{}, v
	}
	var org Organization
	if err := c.post(ctx, "/api/organizations", map[string]any{
		"name": strings.TrimSpace(in.Name),
	}, &org); err != nil {
		return Organization{}, err
	}
	return org, nil
}

// EnsureProject makes a Dokploy project exist under an organization.
func (c *Client) EnsureProject(ctx context.Context, in EnsureProjectInput) (Project, error) {
	if id := strings.TrimSpace(in.ExistingID); id != "" {
		var p Project
		if err := c.get(ctx, "/api/projects/"+url.PathEscape(id), &p); err != nil {
			return Project{}, err
		}
		return p, nil
	}
	if v := requireFields(
		field{"organization_id", in.OrganizationID},
		field{"name", in.Name},
	); v != nil {
		return Project{}, v
	}
	var p Project
	if err := c.post(ctx, "/api/projects", map[string]any{
		"organization_id": strings.TrimSpace(in.OrganizationID),
		"name":            strings.TrimSpace(in.Name),
	}, &p); err != nil {
		return Project{}, err
	}
	return p, nil
}

// EnsureEnvironment makes a Dokploy environment exist under a project.
func (c *Client) EnsureEnvironment(ctx context.Context, in EnsureEnvironmentInput) (Environment, error) {
	if id := strings.TrimSpace(in.ExistingID); id != "" {
		var e Environment
		if err := c.get(ctx, "/api/environments/"+url.PathEscape(id), &e); err != nil {
			return Environment{}, err
		}
		return e, nil
	}
	if v := requireFields(
		field{"project_id", in.ProjectID},
		field{"name", in.Name},
	); v != nil {
		return Environment{}, v
	}
	var e Environment
	if err := c.post(ctx, "/api/environments", map[string]any{
		"project_id": strings.TrimSpace(in.ProjectID),
		"name":       strings.TrimSpace(in.Name),
	}, &e); err != nil {
		return Environment{}, err
	}
	return e, nil
}

// EnsureService makes a Dokploy service (application, compose, or database)
// exist under an environment. Type is always required; Engine is required for
// database services. When in.ExistingID is set the service is fetched and
// verified using the Dokploy resource path that matches Type.
func (c *Client) EnsureService(ctx context.Context, in EnsureServiceInput) (Service, error) {
	if !in.Type.Valid() {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "type",
			Reason: "must be application, compose, or database",
		})
	}
	collection := serviceCollection(in.Type)

	if id := strings.TrimSpace(in.ExistingID); id != "" {
		var svc Service
		if err := c.get(ctx, "/api/"+collection+"/"+url.PathEscape(id), &svc); err != nil {
			return Service{}, err
		}
		return svc, nil
	}

	fields := []field{
		{"environment_id", in.EnvironmentID},
		{"name", in.Name},
	}
	if in.Type == ServiceDatabase {
		fields = append(fields, field{"engine", in.Engine})
	}
	if v := requireFields(fields...); v != nil {
		return Service{}, v
	}

	body := map[string]any{
		"environment_id": strings.TrimSpace(in.EnvironmentID),
		"name":           strings.TrimSpace(in.Name),
	}
	if in.Type == ServiceDatabase {
		body["engine"] = strings.TrimSpace(in.Engine)
	}
	var svc Service
	if err := c.post(ctx, "/api/"+collection, body, &svc); err != nil {
		return Service{}, err
	}
	return svc, nil
}

// EnsureDomain makes a Dokploy domain exist bound to a service.
func (c *Client) EnsureDomain(ctx context.Context, in EnsureDomainInput) (Domain, error) {
	if id := strings.TrimSpace(in.ExistingID); id != "" {
		var d Domain
		if err := c.get(ctx, "/api/domains/"+url.PathEscape(id), &d); err != nil {
			return Domain{}, err
		}
		return d, nil
	}
	if v := requireFields(
		field{"service_id", in.ServiceID},
		field{"host", in.Host},
	); v != nil {
		return Domain{}, v
	}
	var d Domain
	if err := c.post(ctx, "/api/domains", map[string]any{
		"service_id": strings.TrimSpace(in.ServiceID),
		"host":       strings.TrimSpace(in.Host),
		"https":      in.HTTPS,
	}, &d); err != nil {
		return Domain{}, err
	}
	return d, nil
}

// DeployService triggers a deployment of a service and returns the created
// deployment.
func (c *Client) DeployService(ctx context.Context, in DeployServiceInput) (Deployment, error) {
	if v := requireFields(field{"service_id", in.ServiceID}); v != nil {
		return Deployment{}, v
	}
	var dep Deployment
	if err := c.post(ctx, "/api/deployments", map[string]any{
		"service_id": strings.TrimSpace(in.ServiceID),
	}, &dep); err != nil {
		return Deployment{}, err
	}
	return dep, nil
}

// RestartService restarts a service and returns its post-command runtime
// status as reported by Dokploy.
func (c *Client) RestartService(ctx context.Context, in RestartServiceInput) (ServiceStatus, error) {
	if v := requireFields(field{"service_id", in.ServiceID}); v != nil {
		return ServiceStatus{}, v
	}
	var st ServiceStatus
	if err := c.post(ctx, "/api/services/"+url.PathEscape(strings.TrimSpace(in.ServiceID))+"/restart", nil, &st); err != nil {
		return ServiceStatus{}, err
	}
	return st, nil
}

// StartService starts a service and returns its post-command runtime status as
// reported by Dokploy.
func (c *Client) StartService(ctx context.Context, in StartServiceInput) (ServiceStatus, error) {
	if v := requireFields(field{"service_id", in.ServiceID}); v != nil {
		return ServiceStatus{}, v
	}
	var st ServiceStatus
	if err := c.post(ctx, "/api/services/"+url.PathEscape(strings.TrimSpace(in.ServiceID))+"/start", nil, &st); err != nil {
		return ServiceStatus{}, err
	}
	return st, nil
}

// StopService stops a service and returns its post-command runtime status as
// reported by Dokploy.
func (c *Client) StopService(ctx context.Context, in StopServiceInput) (ServiceStatus, error) {
	if v := requireFields(field{"service_id", in.ServiceID}); v != nil {
		return ServiceStatus{}, v
	}
	var st ServiceStatus
	if err := c.post(ctx, "/api/services/"+url.PathEscape(strings.TrimSpace(in.ServiceID))+"/stop", nil, &st); err != nil {
		return ServiceStatus{}, err
	}
	return st, nil
}

// GetDeployment fetches a deployment by ID so a caller can poll its status.
func (c *Client) GetDeployment(ctx context.Context, deploymentID string) (Deployment, error) {
	id := strings.TrimSpace(deploymentID)
	if id == "" {
		return Deployment{}, apierr.InvalidInput(apierr.FieldViolation{
			Field: "deployment_id", Reason: "required",
		})
	}
	var dep Deployment
	if err := c.get(ctx, "/api/deployments/"+url.PathEscape(id), &dep); err != nil {
		return Deployment{}, err
	}
	return dep, nil
}

// ReadDeploymentLogs fetches the captured log output of a deployment.
func (c *Client) ReadDeploymentLogs(ctx context.Context, deploymentID string) (DeploymentLogs, error) {
	id := strings.TrimSpace(deploymentID)
	if id == "" {
		return DeploymentLogs{}, apierr.InvalidInput(apierr.FieldViolation{
			Field: "deployment_id", Reason: "required",
		})
	}
	var logs DeploymentLogs
	if err := c.get(ctx, "/api/deployments/"+url.PathEscape(id)+"/logs", &logs); err != nil {
		return DeploymentLogs{}, err
	}
	return logs, nil
}

// GetServiceStatus fetches the runtime status of a service.
func (c *Client) GetServiceStatus(ctx context.Context, serviceID string) (ServiceStatus, error) {
	id := strings.TrimSpace(serviceID)
	if id == "" {
		return ServiceStatus{}, apierr.InvalidInput(apierr.FieldViolation{
			Field: "service_id", Reason: "required",
		})
	}
	var st ServiceStatus
	if err := c.get(ctx, "/api/services/"+url.PathEscape(id)+"/status", &st); err != nil {
		return ServiceStatus{}, err
	}
	return st, nil
}

// RemoveService removes a service. Removal is idempotent: a service that is
// already gone (Dokploy answers 404) is reported as success, so a retried
// teardown job never fails on its second pass.
func (c *Client) RemoveService(ctx context.Context, in RemoveServiceInput) error {
	if v := requireFields(field{"service_id", in.ServiceID}); v != nil {
		return v
	}
	err := c.del(ctx, "/api/services/"+url.PathEscape(strings.TrimSpace(in.ServiceID)))
	if err == nil {
		return nil
	}
	var ye *yerr.Error
	if stderrors.As(err, &ye) && ye.Code == yerr.CodeNotFound {
		return nil
	}
	return err
}

// serviceCollection maps a ServiceType to its Dokploy REST collection segment.
func serviceCollection(t ServiceType) string {
	switch t {
	case ServiceCompose:
		return "compose"
	case ServiceDatabase:
		return "databases"
	default: // ServiceApplication
		return "applications"
	}
}

// field is a (name, value) pair used for local required-field validation.
type field struct {
	name  string
	value string
}

// requireFields returns an InvalidInput error naming every blank field, or nil
// when all fields are non-blank. Validating locally means an obviously invalid
// intent never reaches Dokploy, and the error carries stable field paths
// without ever echoing the submitted value.
func requireFields(fields ...field) error {
	var violations []apierr.FieldViolation
	for _, f := range fields {
		if strings.TrimSpace(f.value) == "" {
			violations = append(violations, apierr.FieldViolation{
				Field: f.name, Reason: "required",
			})
		}
	}
	if len(violations) == 0 {
		return nil
	}
	return apierr.InvalidInput(violations...)
}
