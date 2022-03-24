package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.mock.MockRuleset;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

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

	@BeforeEach
	public void setup() throws Exception {
		rulesetService = new RulesetService(rulesetRepository, ruleService, repositoryRepository);
		defaultRuleset = MockRuleset.getDefaultRuleset();
		compositeRuleset = MockRuleset.getCompositeRuleset();
		rule = new MockRuleEntity();
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
	public void testDeleteRulesetProvidedException() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					RulesetEntity provided = MockRuleset.getDefaultRuleset();
					provided.setDesignation(RulesetDesignation.PROVIDED);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(provided));
					rulesetService.deleteRuleset(1L);
					BDDMockito.verify(rulesetRepository).delete(defaultRuleset);
				});
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
	public void testEditRulesetProvided() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					RulesetEntity ruleset = MockRuleset.getDefaultRuleset();
					ruleset.setDesignation(RulesetDesignation.PROVIDED);
					BDDMockito.when(rulesetRepository.findById(BDDMockito.anyLong()))
							.thenReturn(Optional.of(ruleset));
					rulesetService.editRuleset(ruleset.toDto());
				});
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
					ruleset.setId(compositeRuleset.getId());
					ruleset.setName(defaultRuleset.getName());
					ruleset.setDescription(compositeRuleset.getDescription());
					ruleset.setDesignation(RulesetDesignation.PRIMARY);
					BDDMockito.when(rulesetRepository.findByName(defaultRuleset.getName()))
							.thenReturn(defaultRuleset);
					BDDMockito.when(rulesetRepository.findById(compositeRuleset.getId()))
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
	public void testSetInheritedRulesetsProvided() throws Exception {
		Assertions.assertThrows(RulesetException.class,
				() -> {
					RulesetEntity ruleset = MockRuleset.getDefaultRuleset();
					BDDMockito.when(rulesetRepository.findById(ruleset.getId()))
							.thenReturn(Optional.of(ruleset));
					ruleset.setDesignation(RulesetDesignation.PROVIDED);
					rulesetService.setInheritedRulesets(ruleset.getId(),
							Collections.singletonList(1L));
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

}
