package com.tracelink.appsec.watchtower.core.metrics;

import java.util.List;

/** Combined scanner availability and queue state for the home page. */
public final class ProcessorHealthModel {
	private final String label;
	private final String tone;
	private final String icon;
	private final long queued;
	private final long active;
	private final List<String> scanners;
	private final List<String> connections;
	private final List<ModuleStatus> modules;
	private final List<IntegrationStatus> integrations;

	public ProcessorHealthModel(String label, String tone, String icon, long queued, long active) {
		this(label, tone, icon, queued, active, List.of(), List.of());
	}

	public ProcessorHealthModel(String label, String tone, String icon, long queued, long active,
			List<String> scanners, List<String> connections) {
		this(label, tone, icon, queued, active, scanners, connections, List.of(), List.of());
	}

	public ProcessorHealthModel(String label, String tone, String icon, long queued, long active,
			List<String> scanners, List<String> connections, List<ModuleStatus> modules,
			List<IntegrationStatus> integrations) {
		this.label = label;
		this.tone = tone;
		this.icon = icon;
		this.queued = queued;
		this.active = active;
		this.scanners = List.copyOf(scanners);
		this.connections = List.copyOf(connections);
		this.modules = List.copyOf(modules);
		this.integrations = List.copyOf(integrations);
	}

	public String getLabel() { return label; }
	public String getTone() { return tone; }
	public String getIcon() { return icon; }
	public long getQueued() { return queued; }
	public long getActive() { return active; }
	public List<String> getScanners() { return scanners; }
	public List<String> getConnections() { return connections; }
	public List<ModuleStatus> getModules() { return modules; }
	public List<IntegrationStatus> getIntegrations() { return integrations; }

	public long countModules(String state) {
		return modules.stream().filter(module -> module.state().equals(state)).count();
	}

	public long countIntegrations(String connection) {
		return integrations.stream().filter(it -> it.connection().equals(connection)).count();
	}

	/** One sentence for screen readers, matching the coloured dots on the status chip. */
	public String getSummary() {
		return label + ". Scanners: " + countModules(ModuleStatus.READY) + " ready, "
				+ countModules(ModuleStatus.SETUP) + " need setup, " + countModules(ModuleStatus.OFF)
				+ " off. Integrations: " + countIntegrations(IntegrationStatus.OK) + " connected, "
				+ countIntegrations(IntegrationStatus.BAD) + " failing, "
				+ countIntegrations(IntegrationStatus.WARN) + " not tested.";
	}
}
