package com.tracelink.appsec.module.checkov.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Entity definition of a Checkov Rule
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "rule_definition")
public class CheckovRuleDefinitionEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "definition_id")
	private long id;

	@Column(name = "checkovtype")
	private String type;

	@Column(name = "entity")
	private String entity;

	@Column(name = "iac")
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

	public CheckovRuleDefinitionDto toDto() {
		CheckovRuleDefinitionDto dto = new CheckovRuleDefinitionDto();
		dto.setId(getId());
		dto.setType(getType());
		dto.setEntity(getEntity());
		dto.setIac(getIac());
		return dto;
	}
}
