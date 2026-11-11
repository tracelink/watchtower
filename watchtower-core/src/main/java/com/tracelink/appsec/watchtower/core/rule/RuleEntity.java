package com.tracelink.appsec.watchtower.core.rule;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Embedded;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Inheritance;
import jakarta.persistence.InheritanceType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

/**
 * Entity description for the rule entity. Contains the fields inherited by all rules, regardless of
 * type.
 *
 * @author mcool
 */
@Entity
@Table(name = "rules")
@Inheritance(strategy = InheritanceType.JOINED)
@jakarta.persistence.EntityListeners(com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionListener.class)
public abstract class RuleEntity {

	@jakarta.persistence.Version
	@Column(name = "definition_version")
	private long persistenceVersion;

	public long getPersistenceVersion() { return persistenceVersion; }
	public void setPersistenceVersion(long value) { persistenceVersion = value; }

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "rule_id")
	private long id;

	@Column(name = "author")
	private String author;

	@Column(name = "name")
	private String name;

	@Column(name = "message")
	@Convert(converter = HexStringConverter.class)
	private String message;

	@Column(name = "external_url")
	private String externalUrl;

	@Column(name = "priority")
	@Enumerated(EnumType.ORDINAL)
	private RulePriority priority;

	@Embedded
	private RuleStewardship stewardship = new RuleStewardship();

	public RuleStewardship getStewardship() {
		return stewardship;
	}

	/** Preserve local stewardship when an import replaces the module-specific definition. */
	public void preserveStewardshipFrom(RuleEntity existing) {
		stewardship = existing.getStewardship().copy();
		persistenceVersion = existing.getPersistenceVersion();
	}

	protected <T extends RuleDto> T withStewardship(T dto) {
		dto.setStewardship(stewardship.copy());
		dto.getStewardship().setRevision(dto.getRevision());
		return dto;
	}

	/**
	 * Refresh before saving changed child parameters: their dirty state alone does not trigger the
	 * parent entity's PreUpdate callback. This also makes import merges persist the new revision.
	 */
	public void refreshRevision() {
		stewardship.setRevision(toDto().getRevision());
	}

	@PrePersist
	protected void recordCreation() {
		long now = System.currentTimeMillis();
		stewardship.setCreatedAt(now);
		stewardship.setUpdatedAt(now);
		refreshRevision();
	}

	@PreUpdate
	protected void recordUpdate() {
		stewardship.setUpdatedAt(System.currentTimeMillis());
		refreshRevision();
	}

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "rule_ruleset", joinColumns = @JoinColumn(name = "rule_id"),
			inverseJoinColumns = @JoinColumn(name = "ruleset_id"))
	@OrderBy("name asc")
	private Set<RulesetEntity> rulesets = new HashSet<>();

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	public RulePriority getPriority() {
		return priority;
	}

	public void setPriority(RulePriority priority) {
		this.priority = priority;
	}

	public Set<RulesetEntity> getRulesets() {
		return rulesets;
	}

	/**
	 * Converts this database entity object into a data transfer object that is more convenient in
	 * some operations. Decodes the Hex values stored in some entity fields.
	 *
	 * @return rule DTO representing this rule entity
	 */
	public abstract RuleDto toDto();

	/**
	 * The designation of this one rule when rules of the same class can differ (a Regex rule is
	 * custom or provided per row), or null when every rule of the class shares one designation.
	 * Cheap: reads a column, unlike {@link #toDto()}.
	 */
	public RuleDesignation designationOfThisRule() {
		return null;
	}

	/**
	 * Converts a plaintext String into a Hex-encoded String and back to support saving to the DB
	 *
	 * @author csmith
	 */
	public static class HexStringConverter implements AttributeConverter<String, String> {

		@Override
		public String convertToDatabaseColumn(String attribute) {
			if (attribute == null) {
				return null;
			}
			return Hex.encodeHexString(attribute.getBytes());
		}

		@Override
		public String convertToEntityAttribute(String dbData) {
			if (dbData == null) {
				return null;
			}
			String decodedField;
			try {
				decodedField = new String(Hex.decodeHex(dbData), StandardCharsets.UTF_8);
			} catch (DecoderException e) {
				decodedField = "";
			}
			return decodedField;
		}

	}
}
