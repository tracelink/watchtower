package com.tracelink.appsec.module.checkov.model;

/**
 * Rule Definition Dto to transfer from Checkov JSON to POJO and Entity
 * 
 * @author csmith
 *
 */
public class CheckovRuleDefinitionDto {
	private long id;

	private String type;

	private String entity;

	private String iac;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getEntity() {
		return entity;
	}

	public void setEntity(String entity) {
		this.entity = entity;
	}

	public String getIac() {
		return iac;
	}

	public void setIac(String iac) {
		this.iac = iac;
	}

	/**
	 * Create the DB Entity for this Definition
	 * 
	 * @return the {@linkplain CheckovRuleDefinitionEntity} for this DTO
	 */
	public CheckovRuleDefinitionEntity toEntity() {
		CheckovRuleDefinitionEntity entity = new CheckovRuleDefinitionEntity();
		entity.setId(getId());
		entity.setEntity(getEntity());
		entity.setIac(getIac());
		entity.setType(getType());
		return entity;
	}
}
