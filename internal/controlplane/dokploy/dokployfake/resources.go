package dokployfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// The service types the fake recognises. They mirror Dokploy's notion of a
// service: a long-running application, a Docker Compose stack, or a managed
// database.
const (
	ServiceApplication = "application"
	ServiceCompose     = "compose"
	ServiceDatabase    = "database"
)

// The deployment lifecycle states the fake exposes. A freshly triggered
// deployment is DeploymentSucceeded so the common path is deterministic; a
// test that needs an in-progress or failed deployment drives it with
// Server.SetDeploymentStatus.
const (
	DeploymentPending   = "pending"
	DeploymentRunning   = "running"
	DeploymentSucceeded = "succeeded"
	DeploymentFailed    = "failed"
)

// StatusRunning is the default runtime status of a freshly created service.
const StatusRunning = "running"

// StatusStopped is the runtime status of a stopped service.
const StatusStopped = "stopped"

// Organization is the top of the Dokploy hierarchy the fake models.
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
	// Engine is set only for database services (e.g. "postgres").
	Engine string `json:"engine,omitempty"`
	// Status is the service's runtime status; it starts at StatusRunning.
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

// BackupRun is one backup execution triggered against a service.
type BackupRun struct {
	ID        string `json:"id"`
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
}

// resourceStore is the fake's in-memory state. It is not safe for concurrent
// use on its own; every access goes through a Server method holding Server.mu.
type resourceStore struct {
	organizations map[string]*Organization
	projects      map[string]*Project
	environments  map[string]*Environment
	services      map[string]*Service
	serviceEnvs   map[string]string
	domains       map[string]*Domain
	deployments   map[string]*Deployment
	backupRuns    map[string]*BackupRun
	// logs maps a deployment ID to its log lines.
	logs map[string][]string
	// counters backs deterministic per-kind ID generation.
	counters map[string]int
}

// newResourceStore returns an empty resourceStore with every map initialised.
func newResourceStore() resourceStore {
	return resourceStore{
		organizations: map[string]*Organization{},
		projects:      map[string]*Project{},
		environments:  map[string]*Environment{},
		services:      map[string]*Service{},
		serviceEnvs:   map[string]string{},
		domains:       map[string]*Domain{},
		deployments:   map[string]*Deployment{},
		backupRuns:    map[string]*BackupRun{},
		logs:          map[string][]string{},
		counters:      map[string]int{},
	}
}

// nextID mints a deterministic ID for the given prefix. It must be called with
// Server.mu held.
func (rs *resourceStore) nextID(prefix string) string {
	rs.counters[prefix]++
	return fmt.Sprintf("%s_%d", prefix, rs.counters[prefix])
}

// newMux builds the fake's request router. The routes cover every operation
// the provisioning worker needs: organization, project, environment,
// application, compose, database, domain, deployment, logs, and status.
func (s *Server) newMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/organizations", s.createOrganization)
	mux.HandleFunc("GET /api/organizations/{id}", s.getOrganization)

	mux.HandleFunc("POST /api/projects", s.createProject)
	mux.HandleFunc("GET /api/projects/{id}", s.getProject)
	mux.HandleFunc("DELETE /api/projects/{id}", s.deleteProject)

	mux.HandleFunc("POST /api/environments", s.createEnvironment)
	mux.HandleFunc("GET /api/environments/{id}", s.getEnvironment)
	mux.HandleFunc("DELETE /api/environments/{id}", s.deleteEnvironment)

	mux.HandleFunc("POST /api/applications", s.createService(ServiceApplication))
	mux.HandleFunc("GET /api/applications/{id}", s.getService)
	mux.HandleFunc("POST /application.saveEnvironment", s.saveApplicationEnvironment)
	mux.HandleFunc("POST /api/compose", s.createService(ServiceCompose))
	mux.HandleFunc("GET /api/compose/{id}", s.getService)
	mux.HandleFunc("POST /compose.update", s.updateCompose)
	mux.HandleFunc("POST /api/databases", s.createService(ServiceDatabase))
	mux.HandleFunc("GET /api/databases/{id}", s.getService)
	mux.HandleFunc("POST /postgres.saveEnvironment", s.saveDatabaseEnvironment("postgres", "postgresId"))
	mux.HandleFunc("POST /mysql.saveEnvironment", s.saveDatabaseEnvironment("mysql", "mysqlId"))
	mux.HandleFunc("POST /mariadb.saveEnvironment", s.saveDatabaseEnvironment("mariadb", "mariadbId"))
	mux.HandleFunc("POST /mongo.saveEnvironment", s.saveDatabaseEnvironment("mongo", "mongoId"))
	mux.HandleFunc("POST /redis.saveEnvironment", s.saveDatabaseEnvironment("redis", "redisId"))

	mux.HandleFunc("GET /api/services/{id}/status", s.getServiceStatus)
	mux.HandleFunc("POST /api/services/{id}/restart", s.restartService)
	mux.HandleFunc("POST /api/services/{id}/rollback", s.rollbackService)
	mux.HandleFunc("POST /api/services/{id}/start", s.startService)
	mux.HandleFunc("POST /api/services/{id}/stop", s.stopService)
	mux.HandleFunc("POST /api/services/{id}/backups", s.runBackup)
	mux.HandleFunc("DELETE /api/services/{id}", s.deleteService)

	mux.HandleFunc("POST /api/domains", s.createDomain)
	mux.HandleFunc("GET /api/domains/{id}", s.getDomain)

	mux.HandleFunc("POST /api/deployments", s.createDeployment)
	mux.HandleFunc("GET /api/deployments/{id}", s.getDeployment)
	mux.HandleFunc("GET /api/deployments/{id}/logs", s.getDeploymentLogs)

	// Catch-all: anything not matched above is a Dokploy-style 404 rather
	// than net/http's plain-text default.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found",
			"no such Dokploy operation")
	})

	return mux
}

// decodeJSON decodes the request body into dst. It returns false (and writes a
// 400) when the body is missing or not valid JSON.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request",
			"the request body is not valid JSON")
		return false
	}
	return true
}

// requireField writes a 400 and returns false when value is blank.
func requireField(w http.ResponseWriter, value, field string) bool {
	if strings.TrimSpace(value) == "" {
		writeError(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("%s is required", field))
		return false
	}
	return true
}

// --- Organizations -------------------------------------------------------

type createOrganizationRequest struct {
	Name string `json:"name"`
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	var req createOrganizationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.Name, "name") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, org := range s.resources.organizations {
		if org.Name == req.Name {
			writeError(w, http.StatusConflict, "conflict",
				"an organization with that name already exists")
			return
		}
	}

	org := &Organization{ID: s.resources.nextID("org"), Name: req.Name}
	s.resources.organizations[org.ID] = org
	writeJSON(w, http.StatusCreated, org)
}

func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	org, ok := s.resources.organizations[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such organization")
		return
	}
	writeJSON(w, http.StatusOK, org)
}

// --- Projects ------------------------------------------------------------

type createProjectRequest struct {
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.OrganizationID, "organization_id") ||
		!requireField(w, req.Name, "name") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.resources.organizations[req.OrganizationID]; !ok {
		writeError(w, http.StatusNotFound, "not_found",
			"the parent organization does not exist")
		return
	}
	for _, p := range s.resources.projects {
		if p.OrganizationID == req.OrganizationID && p.Name == req.Name {
			writeError(w, http.StatusConflict, "conflict",
				"a project with that name already exists in the organization")
			return
		}
	}

	p := &Project{
		ID:             s.resources.nextID("proj"),
		OrganizationID: req.OrganizationID,
		Name:           req.Name,
	}
	s.resources.projects[p.ID] = p
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.resources.projects[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such project")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// deleteProject removes a project plus environments, services, domains, and
// deployments below it. The fake still answers 404 for an unknown ID so the
// client's idempotent teardown mapping is exercised.
func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := r.PathValue("id")
	if _, ok := s.resources.projects[id]; !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such project")
		return
	}
	delete(s.resources.projects, id)
	for environmentID, env := range s.resources.environments {
		if env.ProjectID != id {
			continue
		}
		delete(s.resources.environments, environmentID)
		for serviceID, svc := range s.resources.services {
			if svc.EnvironmentID != environmentID {
				continue
			}
			delete(s.resources.services, serviceID)
			for domainID, d := range s.resources.domains {
				if d.ServiceID == serviceID {
					delete(s.resources.domains, domainID)
				}
			}
			for deploymentID, d := range s.resources.deployments {
				if d.ServiceID == serviceID {
					delete(s.resources.deployments, deploymentID)
				}
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Environments --------------------------------------------------------

type createEnvironmentRequest struct {
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	var req createEnvironmentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.ProjectID, "project_id") ||
		!requireField(w, req.Name, "name") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.resources.projects[req.ProjectID]; !ok {
		writeError(w, http.StatusNotFound, "not_found",
			"the parent project does not exist")
		return
	}
	for _, e := range s.resources.environments {
		if e.ProjectID == req.ProjectID && e.Name == req.Name {
			writeError(w, http.StatusConflict, "conflict",
				"an environment with that name already exists in the project")
			return
		}
	}

	e := &Environment{
		ID:        s.resources.nextID("env"),
		ProjectID: req.ProjectID,
		Name:      req.Name,
	}
	s.resources.environments[e.ID] = e
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.resources.environments[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such environment")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// deleteEnvironment removes an environment plus services, domains, and
// deployments below it. The fake still answers 404 for an unknown ID so the
// client's idempotent teardown mapping is exercised.
func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := r.PathValue("id")
	if _, ok := s.resources.environments[id]; !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such environment")
		return
	}
	delete(s.resources.environments, id)
	for serviceID, svc := range s.resources.services {
		if svc.EnvironmentID != id {
			continue
		}
		delete(s.resources.services, serviceID)
		for domainID, d := range s.resources.domains {
			if d.ServiceID == serviceID {
				delete(s.resources.domains, domainID)
			}
		}
		for deploymentID, d := range s.resources.deployments {
			if d.ServiceID == serviceID {
				delete(s.resources.deployments, deploymentID)
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Services (application / compose / database) -------------------------

type createServiceRequest struct {
	EnvironmentID string `json:"environment_id"`
	Name          string `json:"name"`
	// Engine is required for database services and ignored otherwise.
	Engine string `json:"engine,omitempty"`
}

// createService returns the handler for one service type. The three service
// kinds share creation logic; only the type tag and the database-specific
// engine requirement differ.
func (s *Server) createService(serviceType string) http.HandlerFunc {
	idPrefix := map[string]string{
		ServiceApplication: "app",
		ServiceCompose:     "compose",
		ServiceDatabase:    "db",
	}[serviceType]

	return func(w http.ResponseWriter, r *http.Request) {
		var req createServiceRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if !requireField(w, req.EnvironmentID, "environment_id") ||
			!requireField(w, req.Name, "name") {
			return
		}
		if serviceType == ServiceDatabase && !requireField(w, req.Engine, "engine") {
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if _, ok := s.resources.environments[req.EnvironmentID]; !ok {
			writeError(w, http.StatusNotFound, "not_found",
				"the parent environment does not exist")
			return
		}
		for _, svc := range s.resources.services {
			if svc.EnvironmentID == req.EnvironmentID && svc.Name == req.Name {
				writeError(w, http.StatusConflict, "conflict",
					"a service with that name already exists in the environment")
				return
			}
		}

		svc := &Service{
			ID:            s.resources.nextID(idPrefix),
			EnvironmentID: req.EnvironmentID,
			Name:          req.Name,
			Type:          serviceType,
			Status:        StatusRunning,
		}
		if serviceType == ServiceDatabase {
			svc.Engine = req.Engine
		}
		s.resources.services[svc.ID] = svc
		writeJSON(w, http.StatusCreated, svc)
	}
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

type saveApplicationEnvironmentRequest struct {
	ApplicationID string `json:"applicationId"`
	Env           string `json:"env"`
	BuildArgs     string `json:"buildArgs"`
	BuildSecrets  string `json:"buildSecrets"`
	CreateEnvFile bool   `json:"createEnvFile"`
}

func (s *Server) saveApplicationEnvironment(w http.ResponseWriter, r *http.Request) {
	var req saveApplicationEnvironmentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.ApplicationID, "applicationId") {
		return
	}
	s.saveServiceEnvironment(w, req.ApplicationID, ServiceApplication, req.Env)
}

type updateComposeRequest struct {
	ComposeID string `json:"composeId"`
	Env       string `json:"env"`
}

func (s *Server) updateCompose(w http.ResponseWriter, r *http.Request) {
	var req updateComposeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.ComposeID, "composeId") {
		return
	}
	s.saveServiceEnvironment(w, req.ComposeID, ServiceCompose, req.Env)
}

func (s *Server) saveDatabaseEnvironment(engine, idField string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if !decodeJSON(w, r, &req) {
			return
		}
		id := req[idField]
		if !requireField(w, id, idField) {
			return
		}
		s.saveDatabaseServiceEnvironment(w, id, engine, req["env"])
	}
}

func (s *Server) saveServiceEnvironment(w http.ResponseWriter, serviceID, serviceType, env string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[serviceID]
	if !ok || svc.Type != serviceType {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	s.resources.serviceEnvs[serviceID] = env
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) saveDatabaseServiceEnvironment(w http.ResponseWriter, serviceID, engine, env string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[serviceID]
	if !ok || svc.Type != ServiceDatabase || svc.Engine != engine {
		writeError(w, http.StatusNotFound, "not_found", "no such database")
		return
	}
	s.resources.serviceEnvs[serviceID] = env
	writeJSON(w, http.StatusOK, map[string]any{})
}

type serviceStatusResponse struct {
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
}

func (s *Server) getServiceStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	writeJSON(w, http.StatusOK, serviceStatusResponse{
		ServiceID: svc.ID,
		Status:    svc.Status,
	})
}

func (s *Server) restartService(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	svc.Status = StatusRunning
	writeJSON(w, http.StatusOK, serviceStatusResponse{
		ServiceID: svc.ID,
		Status:    svc.Status,
	})
}

func (s *Server) rollbackService(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	svc.Status = StatusRunning
	writeJSON(w, http.StatusOK, serviceStatusResponse{
		ServiceID: svc.ID,
		Status:    svc.Status,
	})
}

func (s *Server) startService(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	svc.Status = StatusRunning
	writeJSON(w, http.StatusOK, serviceStatusResponse{
		ServiceID: svc.ID,
		Status:    svc.Status,
	})
}

func (s *Server) stopService(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	svc.Status = StatusStopped
	writeJSON(w, http.StatusOK, serviceStatusResponse{
		ServiceID: svc.ID,
		Status:    svc.Status,
	})
}

type runBackupRequest struct {
	BackupID string `json:"backup_id"`
}

func (s *Server) runBackup(w http.ResponseWriter, r *http.Request) {
	var req runBackupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.BackupID, "backup_id") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	serviceID := r.PathValue("id")
	if _, ok := s.resources.services[serviceID]; !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	run := &BackupRun{
		ID:        s.resources.nextID("backup_run"),
		ServiceID: serviceID,
		Status:    DeploymentSucceeded,
	}
	s.resources.backupRuns[run.ID] = run
	writeJSON(w, http.StatusCreated, run)
}

// deleteService removes a service and any domains bound to it. Removal is
// idempotent from the worker's point of view, but the fake still answers 404
// for an unknown ID so the client's own "treat 404 as success" logic is
// exercised rather than hidden.
func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := r.PathValue("id")
	if _, ok := s.resources.services[id]; !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such service")
		return
	}
	delete(s.resources.services, id)
	for domainID, d := range s.resources.domains {
		if d.ServiceID == id {
			delete(s.resources.domains, domainID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Domains -------------------------------------------------------------

type createDomainRequest struct {
	ServiceID string `json:"service_id"`
	Host      string `json:"host"`
	HTTPS     bool   `json:"https"`
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) {
	var req createDomainRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.ServiceID, "service_id") ||
		!requireField(w, req.Host, "host") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.resources.services[req.ServiceID]; !ok {
		writeError(w, http.StatusNotFound, "not_found",
			"the parent service does not exist")
		return
	}
	for _, d := range s.resources.domains {
		if d.Host == req.Host {
			writeError(w, http.StatusConflict, "conflict",
				"that host is already bound to a service")
			return
		}
	}

	d := &Domain{
		ID:        s.resources.nextID("domain"),
		ServiceID: req.ServiceID,
		Host:      req.Host,
		HTTPS:     req.HTTPS,
	}
	s.resources.domains[d.ID] = d
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.resources.domains[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such domain")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// --- Deployments ---------------------------------------------------------

type createDeploymentRequest struct {
	ServiceID string `json:"service_id"`
}

func (s *Server) createDeployment(w http.ResponseWriter, r *http.Request) {
	var req createDeploymentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !requireField(w, req.ServiceID, "service_id") {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.resources.services[req.ServiceID]; !ok {
		writeError(w, http.StatusNotFound, "not_found",
			"the target service does not exist")
		return
	}

	dep := &Deployment{
		ID:        s.resources.nextID("dep"),
		ServiceID: req.ServiceID,
		// Deployments succeed immediately by default so the common worker
		// path is deterministic; SetDeploymentStatus overrides this.
		Status: DeploymentSucceeded,
	}
	s.resources.deployments[dep.ID] = dep
	s.resources.logs[dep.ID] = []string{
		fmt.Sprintf("queued deployment %s for service %s", dep.ID, dep.ServiceID),
		"pulling image",
		"starting container",
		"deployment succeeded",
	}
	writeJSON(w, http.StatusCreated, dep)
}

func (s *Server) getDeployment(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dep, ok := s.resources.deployments[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such deployment")
		return
	}
	writeJSON(w, http.StatusOK, dep)
}

type deploymentLogsResponse struct {
	DeploymentID string   `json:"deployment_id"`
	Lines        []string `json:"lines"`
}

func (s *Server) getDeploymentLogs(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := r.PathValue("id")
	if _, ok := s.resources.deployments[id]; !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such deployment")
		return
	}
	lines := s.resources.logs[id]
	out := make([]string, len(lines))
	copy(out, lines)
	writeJSON(w, http.StatusOK, deploymentLogsResponse{DeploymentID: id, Lines: out})
}

// --- Test-control helpers ------------------------------------------------

// SetDeploymentStatus overrides a deployment's status so a test can simulate
// an in-progress or failed deployment. It reports whether the deployment
// exists.
func (s *Server) SetDeploymentStatus(deploymentID, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	dep, ok := s.resources.deployments[deploymentID]
	if !ok {
		return false
	}
	dep.Status = status
	return true
}

// SetServiceStatus overrides a service's runtime status so a test can simulate
// a crashed or restarting service. It reports whether the service exists.
func (s *Server) SetServiceStatus(serviceID, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.resources.services[serviceID]
	if !ok {
		return false
	}
	svc.Status = status
	return true
}

// ApplicationEnv returns the saved environment for an application service.
func (s *Server) ApplicationEnv(applicationID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resources.serviceEnvs[applicationID]
}
