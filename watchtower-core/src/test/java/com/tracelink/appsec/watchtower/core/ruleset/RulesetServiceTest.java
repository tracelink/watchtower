package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mock.MockRule;
import com.tracelink.appsec.watchtower.core.mock.MockRuleDto;
import com.tracelink.appsec.watchtower.core.mock.MockRuleset;
import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRuleImpexModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractRulesetImpexModel;
import com.tracelink.appsec.watchtower.core.module.interpreter.jackson.AbstractXmlRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.scm.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.RepositoryRepository;

@ExtendWith(SpringExtension.class)
public class RulesetServiceTest {
	@MockBean
	private RulesetRepository rulesetRepository;
	@MockBean
	private RuleService ruleService;
	@MockBean
	private RepositoryRepository repositoryRepository;
	@Mock
	private HttpServletResponse mockResponse;

	private RulesetService rulesetService;
	private RulesetEntity defaultRuleset;
	private RulesetEntity compositeRuleset;
	private RuleEntity rule;
	private InputStream is;

	@BeforeEach
	public void setup() throws Exception {
		rulesetService = new RulesetService(rulesetRepository, ruleService, repositoryRepository);
		defaultRuleset = MockRuleset.getDefaultRuleset();
		compositeRuleset = MockRuleset.getCompositeRuleset();
		rule = new MockRule();
		is = new FileInputStream(
				Paths.get(getClass().getResource("/xml/mockRuleset.xml").toURI()).toFile());
	}

	@Test
	public void testGetRulesets() {
		List<RulesetEntity> rulesets = Arrays.asList(compositeRuleset, defaultRuleset);
		BDDMockito.when(rulesetRepository.findAll()).thenReturn(rulesets);
		List<RulesetDto> actual = rulesetService.getRulesets();
		Assertions.assertEquals(2, actual.size());
		Assertions.assertEquals(defaultRuleset.getName(), actual.get(0).getName());
		Assertions.assertEquals(compositeRuleset.getName(), actual.get(1).getName());
	}

	@Test
	public void testCreateRuleset() throws Exception {
		BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.empty());
		RulesetEntity ruleset = rulesetService
				.createRuleset(defaultRuleset.getName(), defaultRuleset.getDescription(),
						RulesetDesignation.PRIMARY);
		Assertions.assertEquals(defaultRuleset.getName(), ruleset.getName());
		Assertions.assertEquals(defaultRuleset.getDescription(), ruleset.getDescription());
		Assertions.assertTrue(ruleset.getRulesets().isEmpty());
		Assertions.assertTrue(ruleset.getRules().isEmpty());
	}

	@Test
	public void testCreateRulesetNullName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.createRuleset(null, "foo", RulesetDesignation.SUPPORTING);
				});
	}

	@Test
	public void testCreateRulesetEmptyName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.createRuleset("", "foo", RulesetDesignation.SUPPORTING);
				});
	}

	@Test
	public void testCreateRulesetNullDescription() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.createRuleset("foo", null, RulesetDesignation.SUPPORTING);
				});
	}

	@Test
	public void testCreateRulesetEmptyDescription() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.createRuleset("foo", "", RulesetDesignation.SUPPORTING);
				});
	}

	@Test
	public void testCreateRulesetNullDesignation() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.createRuleset("foo", "bar", null);
				});
	}

	@Test
	public void testCreateRulesetDefaultAlreadyExists() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					rulesetService
							.createRuleset(defaultRuleset.getName(),
									defaultRuleset.getDescription(),
									RulesetDesignation.DEFAULT);
				});
	}

	@Test
	public void testCreateRulesetNameCollision() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findByName(defaultRuleset.getName()))
							.thenReturn(defaultRuleset);
					rulesetService.createRuleset(defaultRuleset.getName(),
							defaultRuleset.getDescription(),
							RulesetDesignation.SUPPORTING);
				});
	}

	@Test
	public void testDeleteRuleset() throws Exception {
		BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(defaultRuleset));
		rulesetService.deleteRuleset(1L);
		BDDMockito.verify(rulesetRepository).delete(defaultRuleset);
	}

	@Test
	public void testDeleteRulesetRemoveRepoReferences() throws Exception {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(compositeRuleset);
		BDDMockito.when(repositoryRepository.findAll()).thenReturn(Collections.singletonList(repo));
		BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(compositeRuleset));
		BDDMockito.when(rulesetRepository.findByDesignation(RulesetDesignation.DEFAULT))
				.thenReturn(defaultRuleset);
		rulesetService.deleteRuleset(1L);
		BDDMockito.verify(repositoryRepository).save(repo);
		BDDMockito.verify(rulesetRepository).delete(compositeRuleset);
		Assertions.assertEquals(defaultRuleset, repo.getRuleset());
	}

	@Test
	public void testDeleteRulesetNotFound() throws Exception {
		Assertions.assertThrows(RulesetNotFoundException.class,
				() -> {
					rulesetService.deleteRuleset(1L);
				});
	}

	@Test
	public void testEditRuleset() throws Exception {
		String complex = "Complex";
		String complexDesc = "A ruleset composed of other rulesets.";
		RulesetDto ruleset = new RulesetDto();
		ruleset.setId(compositeRuleset.getId());
		ruleset.setName(complex);
		ruleset.setDescription(complexDesc);
		ruleset.setDesignation(RulesetDesignation.PRIMARY);
		ruleset.setBlockingLevel(RulePriority.HIGH);
		BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(compositeRuleset));
		rulesetService.editRuleset(ruleset);
		Assertions.assertEquals(complex, compositeRuleset.getName());
		Assertions.assertEquals(complexDesc, compositeRuleset.getDescription());
		Assertions.assertEquals(RulesetDesignation.PRIMARY, compositeRuleset.getDesignation());
		Assertions.assertEquals(RulePriority.HIGH, compositeRuleset.getBlockingLevel());
	}

	@Test
	public void testEditRulesetSupporting() throws Exception {
		String complex = "Complex";
		String complexDesc = "A ruleset composed of other rulesets.";
		RulesetDto ruleset = new RulesetDto();
		ruleset.setId(compositeRuleset.getId());
		ruleset.setName(complex);
		ruleset.setDescription(complexDesc);
		ruleset.setDesignation(RulesetDesignation.SUPPORTING);
		ruleset.setBlockingLevel(RulePriority.HIGH); // High will not be set since it is supporting
		BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(compositeRuleset));
		rulesetService.editRuleset(ruleset);
		Assertions.assertEquals(complex, compositeRuleset.getName());
		Assertions.assertEquals(complexDesc, compositeRuleset.getDescription());
		Assertions.assertEquals(RulesetDesignation.SUPPORTING, compositeRuleset.getDesignation());
		Assertions.assertNull(compositeRuleset.getBlockingLevel());
	}

	@Test
	public void testEditRulesetNotFound()
			throws Exception {
		Assertions.assertThrows(RulesetNotFoundException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(1L);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.empty());
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetNullName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName(null);
					ruleset.setDescription("foo");
					ruleset.setDesignation(RulesetDesignation.PRIMARY);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetEmptyName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName("");
					ruleset.setDescription("foo");
					ruleset.setDesignation(RulesetDesignation.PRIMARY);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetNullDescription() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName("foo");
					ruleset.setDescription(null);
					ruleset.setDesignation(RulesetDesignation.PRIMARY);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetEmptyDescription() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName("foo");
					ruleset.setDescription("");
					ruleset.setDesignation(RulesetDesignation.PRIMARY);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetNullDesignation() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName("foo");
					ruleset.setDescription("bar");
					ruleset.setDesignation(null);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetDefaultDesignation() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName("foo");
					ruleset.setDescription("bar");
					ruleset.setDesignation(RulesetDesignation.DEFAULT);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetSameName() throws Exception {
		String newDesc = "A ruleset composed of other rulesets.";
		RulesetDto ruleset = new RulesetDto();
		ruleset.setId(2L);
		ruleset.setName(compositeRuleset.getName());
		ruleset.setDescription(newDesc);
		ruleset.setDesignation(RulesetDesignation.PRIMARY);
		BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(compositeRuleset));
		rulesetService.editRuleset(ruleset);
		Assertions.assertEquals("Composite", compositeRuleset.getName());
		Assertions.assertEquals(newDesc, compositeRuleset.getDescription());
	}

	@Test
	public void testEditRulesetNameCollision() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName(defaultRuleset.getName());
					ruleset.setDescription(compositeRuleset.getDescription());
					ruleset.setDesignation(RulesetDesignation.PRIMARY);
					BDDMockito.when(rulesetRepository.findByName(defaultRuleset.getName()))
							.thenReturn(defaultRuleset);
					BDDMockito.when(rulesetRepository.findById(2L))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testEditRulesetSupportingInheritsFromPrimary() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					RulesetDto ruleset = new RulesetDto();
					ruleset.setId(2L);
					ruleset.setName(compositeRuleset.getName());
					ruleset.setDescription(compositeRuleset.getDescription());
					ruleset.setDesignation(RulesetDesignation.SUPPORTING);
					BDDMockito.when(rulesetRepository.findById(2L))
							.thenReturn(Optional.of(compositeRuleset));
					compositeRuleset.setRulesets(Collections.singleton(defaultRuleset));
					rulesetService.editRuleset(ruleset);
				});
	}

	@Test
	public void testSetInheritedRulesets() throws Exception {
		BDDMockito.when(rulesetRepository.findById(1L)).thenReturn(Optional.of(defaultRuleset));
		BDDMockito.when(rulesetRepository.findById(2L)).thenReturn(Optional.of(compositeRuleset));
		rulesetService.setInheritedRulesets(2L, Collections.singletonList(1L));
		BDDMockito.verify(rulesetRepository).saveAndFlush(compositeRuleset);
		Assertions.assertTrue(compositeRuleset.getRulesets().contains(defaultRuleset));
	}

	@Test
	public void testSetInheritedRulesetsParentNotFound() throws Exception {
		Assertions.assertThrows(RulesetNotFoundException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(1L))
							.thenReturn(Optional.of(defaultRuleset));
					BDDMockito.when(rulesetRepository.findById(2L)).thenReturn(Optional.empty());
					rulesetService.setInheritedRulesets(2L, Collections.singletonList(1L));
				});
	}

	@Test
	public void testSetInheritedRulesetsChildNotFound() throws Exception {
		Assertions.assertThrows(RulesetNotFoundException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(1L)).thenReturn(Optional.empty());
					BDDMockito.when(rulesetRepository.findById(2L))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.setInheritedRulesets(2L, Collections.singletonList(1L));
				});
	}

	@Test
	public void testSetInheritedRulesetsParentEqualsChild() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(compositeRuleset));
					rulesetService.setInheritedRulesets(2L, Collections.singletonList(2L));
				});
	}

	@Test
	public void testSetInheritedRulesetsChildContainsParent() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(1L))
							.thenReturn(Optional.of(defaultRuleset));
					BDDMockito.when(rulesetRepository.findById(2L))
							.thenReturn(Optional.of(compositeRuleset));
					defaultRuleset.getRulesets().add(compositeRuleset);
					rulesetService.setInheritedRulesets(2L, Collections.singletonList(1L));
				});
	}

	@Test
	public void testSetInheritedRulesetsSupportingInheritsFromPrimary() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(1L))
							.thenReturn(Optional.of(defaultRuleset));
					BDDMockito.when(rulesetRepository.findById(2L))
							.thenReturn(Optional.of(compositeRuleset));
					compositeRuleset.setDesignation(RulesetDesignation.SUPPORTING);
					rulesetService.setInheritedRulesets(2L, Collections.singletonList(1L));
				});
	}

	@Test
	public void testSetRules() throws Exception {
		BDDMockito.when(rulesetRepository.findById(defaultRuleset.getId()))
				.thenReturn(Optional.of(defaultRuleset));
		BDDMockito.when(ruleService.getRule(rule.getId())).thenReturn(rule);
		rulesetService.setRules(defaultRuleset.getId(), Collections.singletonList(rule.getId()));
		BDDMockito.verify(rulesetRepository).saveAndFlush(defaultRuleset);
		Assertions.assertTrue(defaultRuleset.getRules().contains(rule));
	}

	@Test
	public void testSetRulesRulesetNotFound() throws Exception {
		Assertions.assertThrows(RulesetNotFoundException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(defaultRuleset.getId()))
							.thenReturn(Optional.empty());
					rulesetService.setRules(defaultRuleset.getId(),
							Collections.singletonList(rule.getId()));
				});
	}

	@Test
	public void testSetPMDRulesRuleNotFound() throws Exception {
		BDDMockito.when(rulesetRepository.findById(defaultRuleset.getId()))
				.thenReturn(Optional.of(defaultRuleset));
		try {
			rulesetService.setRules(defaultRuleset.getId(),
					Collections.singletonList(rule.getId()));
		} catch (RuleNotFoundException e) {
			BDDMockito.verify(rulesetRepository, Mockito.times(0)).saveAndFlush(defaultRuleset);
			Assertions.assertTrue(defaultRuleset.getRules().isEmpty());
		}
	}

	@Test
	public void testSetDefaultRuleset() throws Exception {
		BDDMockito.when(rulesetRepository.findByDesignation(RulesetDesignation.DEFAULT))
				.thenReturn(defaultRuleset);
		BDDMockito.when(rulesetRepository.findById(compositeRuleset.getId()))
				.thenReturn(Optional.of(compositeRuleset));
		rulesetService.setDefaultRuleset(compositeRuleset.getId());
		BDDMockito.verify(rulesetRepository).save(defaultRuleset);
		BDDMockito.verify(rulesetRepository).saveAndFlush(compositeRuleset);
		Assertions.assertEquals(RulesetDesignation.PRIMARY, defaultRuleset.getDesignation());
		Assertions.assertEquals(RulesetDesignation.DEFAULT, compositeRuleset.getDesignation());
	}

	@Test
	public void testSetDefaultRulesetSupporting() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					BDDMockito.when(rulesetRepository.findById(compositeRuleset.getId()))
							.thenReturn(Optional.of(compositeRuleset));
					compositeRuleset.setDesignation(RulesetDesignation.SUPPORTING);
					rulesetService.setDefaultRuleset(compositeRuleset.getId());
				});
	}

	@Test
	public void testSetDefaultRulesetNone() throws Exception {
		BDDMockito.when(rulesetRepository.findByDesignation(RulesetDesignation.DEFAULT))
				.thenReturn(defaultRuleset);
		rulesetService.setDefaultRuleset(-1L);
		BDDMockito.verify(rulesetRepository).saveAndFlush(defaultRuleset);
		Assertions.assertEquals(RulesetDesignation.PRIMARY, defaultRuleset.getDesignation());
	}

	@Test
	public void testSetDefaultRulesetNoneNoExistingDefault() throws Exception {
		BDDMockito.when(rulesetRepository.findByDesignation(RulesetDesignation.DEFAULT))
				.thenReturn(null);
		rulesetService.setDefaultRuleset(-1L);
		BDDMockito.verify(rulesetRepository, Mockito.times(0))
				.saveAndFlush(BDDMockito.any(RulesetEntity.class));
	}

	@Test
	public void testRemoveRuleFromAllRulesets() throws Exception {
		defaultRuleset.setRules(new HashSet<>(Arrays.asList(rule)));
		BDDMockito.when(rulesetRepository.findAll())
				.thenReturn(Collections.singletonList(defaultRuleset));
		BDDMockito.when(ruleService.getRule(rule.getId())).thenReturn(rule);
		rulesetService.removeRuleFromAllRulesets(rule.getId());
		BDDMockito.verify(rulesetRepository, Mockito.times(1)).saveAll(BDDMockito.anyIterable());
		BDDMockito.verify(rulesetRepository, Mockito.times(1)).flush();
		Assertions.assertFalse(defaultRuleset.getRules().contains(rule));
	}

	@Test
	public void testImportRulesetNullUser() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.importRuleset("mock", is, null);
				});
	}

	@Test
	public void testImportRulesetNoXmlModel() throws Exception {
		Assertions.assertThrows(ModuleNotFoundException.class,
				() -> {
					rulesetService.importRuleset("mock", is, new UserEntity());
				});
	}

	@Test
	public void testImportRulesetInvalidRule() throws Exception {
		rulesetService.registerInterpreter("Mock",
				new MockRulesetInterpreter(MockInvalidRulesetXmlModel.class));
		try {
			rulesetService.importRuleset("mock", is, new UserEntity());
			Assertions.fail("Exception should have been thrown");
		} catch (RulesetException e) {
			Assertions.assertEquals(
					"The rule with the name \"Rule Name\" is invalid: Message cannot be empty.",
					e.getMessage());
		}
	}

	@Test
	public void testImportRulesetRuleAlreadyExists() throws Exception {
		rulesetService.registerInterpreter("Mock",
				new MockRulesetInterpreter(MockRulesetXmlModel.class));
		BDDMockito.when(ruleService.getRule(BDDMockito.anyString()))
				.thenReturn(BDDMockito.mock(RuleEntity.class));
		try {
			rulesetService.importRuleset("mock", is, new UserEntity());
			Assertions.fail("Exception should have been thrown");
		} catch (RulesetException e) {
			Assertions.assertEquals("A rule with the name \"Rule Name\" already exists.",
					e.getMessage());
		}
	}

	@Test
	public void testImportRulesetRulesetAlreadyExists() throws Exception {
		rulesetService.registerInterpreter("Mock",
				new MockRulesetInterpreter(MockRulesetXmlModel.class));
		BDDMockito.when(ruleService.getRule(rule.getName())).thenReturn(null);
		BDDMockito.when(rulesetRepository.findByName("Mock-Ruleset")).thenReturn(defaultRuleset);
		BDDMockito
				.when(ruleService.importRules(BDDMockito.anySet(),
						BDDMockito.anyString()))
				.thenReturn(Arrays.asList(rule));
		rulesetService.importRuleset("mock", is, new UserEntity());

		BDDMockito.verify(rulesetRepository, Mockito.times(1)).saveAndFlush(defaultRuleset);
		Assertions.assertFalse(defaultRuleset.getRules().isEmpty());
		Assertions.assertEquals(rule, defaultRuleset.getRules().iterator().next());
	}

	@Test
	public void testImportRulesetCreateRuleset() throws Exception {
		rulesetService.registerInterpreter("Mock",
				new MockRulesetInterpreter(MockRulesetXmlModel.class));
		BDDMockito.when(ruleService.getRule(rule.getName())).thenReturn(null);
		BDDMockito
				.when(ruleService.importRules(BDDMockito.anySet(),
						BDDMockito.anyString()))
				.thenReturn(Arrays.asList(rule));
		rulesetService.importRuleset("mock", is, new UserEntity());

		ArgumentCaptor<RulesetEntity> rulesetCaptor = ArgumentCaptor.forClass(RulesetEntity.class);
		BDDMockito.verify(rulesetRepository, Mockito.times(2))
				.saveAndFlush(rulesetCaptor.capture());
		RulesetEntity ruleset = rulesetCaptor.getValue();
		Assertions.assertFalse(ruleset.getRules().isEmpty());
		Assertions.assertEquals(rule, ruleset.getRules().iterator().next());
	}

	@Test
	public void testExportRulesetNoRules() throws Exception {
		BDDMockito.when(rulesetRepository.findById(defaultRuleset.getId()))
				.thenReturn(Optional.of(defaultRuleset));
		try {
			rulesetService.exportRuleset(defaultRuleset.getId(), mockResponse);
			Assertions.fail("Exception should have been thrown");
		} catch (RulesetException e) {
			Assertions.assertEquals("Ruleset with name \"Default\" does not contain any rules.",
					e.getMessage());
		}
	}

	@Test
	public void testExportRuleset() throws Exception {
		defaultRuleset.setRules(Collections.singleton(rule));
		rulesetService.registerInterpreter("Mock",
				new MockRulesetInterpreter(MockRulesetXmlModel.class));
		BDDMockito.when(rulesetRepository.findById(defaultRuleset.getId()))
				.thenReturn(Optional.of(defaultRuleset));
		MockOutputStream outputStream = new MockOutputStream();
		BDDMockito.when(mockResponse.getOutputStream()).thenReturn(outputStream);
		rulesetService.exportRuleset(defaultRuleset.getId(), mockResponse);
		BDDMockito.verify(mockResponse).setStatus(HttpServletResponse.SC_OK);
		BDDMockito.verify(mockResponse).setHeader(HttpHeaders.CONTENT_TYPE, "application/zip");
		BDDMockito.verify(mockResponse)
				.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"Default.zip\"");

		try (ZipInputStream zipInputStream = new ZipInputStream(
				new ByteArrayInputStream(outputStream.getBaos().toByteArray()))) {
			ZipEntry zipEntry = zipInputStream.getNextEntry();
			Assertions.assertEquals("Default-Mock.xml", zipEntry.getName());
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int b = zipInputStream.read();
			while (b >= 0) {
				baos.write(b);
				b = zipInputStream.read();
			}
			zipInputStream.closeEntry();
			Assertions.assertEquals(
					"<ruleset name=\"Default\"><description>The default set of rules.</description><rule name=\"Mock Rule\"/></ruleset>",
					new String(baos.toByteArray()));
			Assertions.assertNull(zipInputStream.getNextEntry());
		}
	}

	@Test
	public void testExportRulesetNoRulesOfOneType() throws Exception {
		defaultRuleset.setRules(Collections.singleton(rule));
		rulesetService.registerInterpreter("Mock",
				new MockRulesetInterpreter(MockRulesetXmlModel.class));
		rulesetService.registerInterpreter("OtherMock", new MockRulesetInterpreter(null));
		BDDMockito.when(rulesetRepository.findById(defaultRuleset.getId()))
				.thenReturn(Optional.of(defaultRuleset));
		MockOutputStream outputStream = new MockOutputStream();
		BDDMockito.when(mockResponse.getOutputStream()).thenReturn(outputStream);
		rulesetService.exportRuleset(defaultRuleset.getId(), mockResponse);
		BDDMockito.verify(mockResponse).setStatus(HttpServletResponse.SC_OK);
		BDDMockito.verify(mockResponse).setHeader(HttpHeaders.CONTENT_TYPE, "application/zip");
		BDDMockito.verify(mockResponse)
				.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"Default.zip\"");

		try (ZipInputStream zipInputStream = new ZipInputStream(
				new ByteArrayInputStream(outputStream.getBaos().toByteArray()))) {
			ZipEntry zipEntry = zipInputStream.getNextEntry();
			Assertions.assertEquals("Default-Mock.xml", zipEntry.getName());
			zipInputStream.closeEntry();
			Assertions.assertNull(zipInputStream.getNextEntry());
		}
	}

	@Test
	public void testRegisterInterpreterBlankModuleName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.registerInterpreter("\t",
							new MockRulesetInterpreter(MockRulesetXmlModel.class));
				});
	}

	@Test
	public void testRegisterInterpreterNullModelClass() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					rulesetService.registerInterpreter("Mock", null);
				});
	}

	@Test
	public void testRegisterInterpreterDuplicateModule() throws Exception {
		Assertions.assertThrows(ModuleException.class,
				() -> {
					rulesetService.registerInterpreter("Mock",
							new MockRulesetInterpreter(MockRulesetXmlModel.class));
					rulesetService.registerInterpreter("Mock",
							new MockRulesetInterpreter(MockRulesetXmlModel.class));
				});
	}

	@Test
	public void testGetDefaultNull() {
		RulesetEntity ruleset = rulesetService.getDefaultRuleset();
		Assertions.assertNull(ruleset);
	}

	@Test
	public void testGetDefaultRulesetAlreadyExists() {
		RulesetEntity ruleset = new RulesetEntity();
		BDDMockito.when(rulesetRepository.findByDesignation(RulesetDesignation.DEFAULT))
				.thenReturn(ruleset);
		Assertions.assertEquals(ruleset, rulesetService.getDefaultRuleset());
		BDDMockito.verify(rulesetRepository, Mockito.times(0)).saveAndFlush(ruleset);
	}

	@Test
	public void testDownloadExampleRuleset() throws Exception {
		String module = "module";
		String ext = "js";
		String content = "foo";
		IRulesetInterpreter mockInterpreter =
				BDDMockito.mock(IRulesetInterpreter.class);
		rulesetService.registerInterpreter(module, mockInterpreter);
		ByteArrayInputStream bais = new ByteArrayInputStream(content.getBytes());
		BDDMockito.when(mockInterpreter.exportExampleRuleset()).thenReturn(bais);
		BDDMockito.when(mockInterpreter.getExtension()).thenReturn(ext);
		InputStreamResource isr = rulesetService.downloadExampleRuleset(module);
		MatcherAssert.assertThat(isr.getFilename(), Matchers.is(module + "." + ext));
		Assertions.assertEquals(isr.contentLength(), -1L);
		Assertions.assertEquals(IOUtils.toString(isr.getInputStream(), Charset.defaultCharset()),
				content);
	}

	@Test
	public void testDownloadExampleRulesetNull() throws Exception {
		String module = "module";
		IRulesetInterpreter mockInterpreter =
				BDDMockito.mock(IRulesetInterpreter.class);
		rulesetService.registerInterpreter(module, mockInterpreter);
		BDDMockito.when(mockInterpreter.exportExampleRuleset()).thenReturn(null);
		InputStreamResource isr = rulesetService.downloadExampleRuleset(module);
		Assertions.assertNull(isr);
	}

	private static class MockRulesetInterpreter extends AbstractXmlRulesetInterpreter {
		private Class<? extends AbstractRulesetImpexModel> xmlModelClass;

		MockRulesetInterpreter(Class<? extends AbstractRulesetImpexModel> xmlModelClass) {
			this.xmlModelClass = xmlModelClass;
		}

		@Override
		protected Class<? extends AbstractRulesetImpexModel> getRulesetModelClass() {
			return xmlModelClass;
		}

		@Override
		protected AbstractRulesetImpexModel fromDto(RulesetDto rulesetDto) {
			if (xmlModelClass == null) {
				return null;
			}
			MockRulesetXmlModel rulesetXmlModel = new MockRulesetXmlModel();
			rulesetXmlModel.setName(rulesetDto.getName());
			rulesetXmlModel.setDescription(rulesetDto.getDescription());
			rulesetXmlModel.setRules(Collections.singleton(new MockRuleXmlModel()));
			return rulesetXmlModel;
		}

		@Override
		protected RulesetDto makeExampleRuleset() {
			return null;
		}
	}

	@JacksonXmlRootElement(localName = "ruleset")
	private static class MockRulesetXmlModel extends AbstractRulesetImpexModel {
		@JacksonXmlProperty(isAttribute = true)
		private String name;
		@JacksonXmlProperty
		private String description;
		@JacksonXmlProperty(localName = "rule")
		private Set<MockRuleXmlModel> rules;

		@Override
		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		@Override
		public String getDescription() {
			return description;
		}

		public void setDescription(String description) {
			this.description = description.trim();
		}

		@Override
		public Set<? extends AbstractRuleImpexModel> getRules() {
			return rules;
		}

		public void setRules(Set<MockRuleXmlModel> rules) {
			this.rules = rules;
		}
	}

	private static class MockRuleXmlModel extends AbstractRuleImpexModel {
		@JacksonXmlProperty(isAttribute = true)
		private String name = "Mock Rule";

		@Override
		public RuleDto toDto() {
			RuleDto dto = new MockRule().toDto();
			dto.setId(null);
			dto.setAuthor(null);
			return dto;
		}
	}

	@JacksonXmlRootElement(localName = "ruleset")
	private static class MockInvalidRulesetXmlModel extends AbstractRulesetImpexModel {
		@JacksonXmlProperty(isAttribute = true)
		private String name;
		@JacksonXmlProperty
		private String description;
		@JacksonXmlProperty(localName = "rule")
		private Set<MockInvalidRuleXmlModel> rules;

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public Set<? extends AbstractRuleImpexModel> getRules() {
			return rules;
		}

	}

	private static class MockInvalidRuleXmlModel extends AbstractRuleImpexModel {
		@Override
		public RuleDto toDto() {
			MockRuleDto dto = new MockRule().toDto();
			dto.setId(null);
			dto.setAuthor(null);
			dto.setMessage("");
			return dto;
		}
	}

	private static class MockOutputStream extends ServletOutputStream {
		private ByteArrayOutputStream baos = new ByteArrayOutputStream();

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setWriteListener(WriteListener writeListener) {
		}

		@Override
		public void write(int b) throws IOException {
			baos.write(b);
		}

		ByteArrayOutputStream getBaos() {
			return baos;
		}
	}
}
