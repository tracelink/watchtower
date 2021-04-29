package com.tracelink.appsec.watchtower.core.rule;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import javax.persistence.AttributeConverter;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * Entity description for the rule entity. Contains the fields inherited by all rules, regardless of
 * type.
 *
 * @author mcool
 */
@Entity
@Table(name = "rules")
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class RuleEntity {

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

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "rule_ruleset", joinColumns = @JoinColumn(name = "rule_id"),
			inverseJoinColumns = @JoinColumn(name = "ruleset_id"))
	@OrderBy("name asc")
	private Set<RulesetEntity> rulesets = new HashSet<>();

	public long getId() {
		return id;
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
