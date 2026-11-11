package com.tracelink.appsec.watchtower.core.scan.repository;

import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Sort;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanExporter;

/**
 * The inventory as CSV: an export of what the current filter shows, and an import that sets
 * owners, labels, criticality and ruleset for many repositories at once. The import is checked
 * row by row before anything is written, then written as Hibernate entity changes.
 *
 * @author Watchtower
 */
@Service
public class RepositoryCsvService {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryCsvService.class);

	/** The largest file an import accepts. */
	public static final long MAX_BYTES = 1024 * 1024;

	/** The most rows an import accepts. */
	public static final int MAX_ROWS = 5_000;

	static final int MAX_ERRORS = 20;

 private static final String EXPORT_HEADER="repo,project,team,owner,labels,criticality,ruleset,status\r\n";
 private record CsvUpdate(long id,boolean updateTeam,String team,boolean updateOwner,String owner,
   boolean updateLabels,String labels,Integer criticality,boolean updateRuleset,Long rulesetId) { }

	private final RepositoryRepository repoRepo;

	private final RepositoryStatusService statuses;

	private final RulesetService rulesets;

	private final LedgerRepository persistence;

	public RepositoryCsvService(RepositoryRepository repoRepo, RepositoryStatusService statuses,
			RulesetService rulesets, LedgerRepository persistence) {
		this.repoRepo = repoRepo;
		this.statuses = statuses;
		this.rulesets = rulesets;
		this.persistence = persistence;
	}

	/**
	 * Writes every repository the filter matches, formula-safe.
	 */
	public void export(ScanType type, String apiLabel, RepositoryFilter filter, Writer out)
			throws IOException {
		out.write(EXPORT_HEADER);
		for (RepositoryEntity repo : repoRepo.findAll(statuses.matching(type, apiLabel, filter),
				Sort.by("repoName"))) {
			out.write(String.join(",", RepoScanExporter.cell(repo.getRepoName()),
					RepoScanExporter.cell(repo.getProjectKey()),
					RepoScanExporter.cell(repo.getTeam()),
					RepoScanExporter.cell(repo.getOwnerName()),
					RepoScanExporter.cell(String.join(" ", repo.getLabels())),
					RepoScanExporter.cell(RepoCriticality.of(repo.getCriticality())
							.getDisplayName()),
					RepoScanExporter.cell(repo.getRuleset() == null ? "None"
							: repo.getRuleset().getName()),
					RepoScanExporter.cell(statuses.statusOf(repo).labelFor(repo.getScanType() instanceof com.tracelink.appsec.watchtower.core.scan.image.ImageScanType))));
			out.write("\r\n");
		}
		out.flush();
	}

	/**
	 * Sets team, owner, labels, criticality and (optionally) ruleset from a CSV whose header
	 * names at least {@code repo}. Other columns, such as an export's project and status, are
	 * ignored.
	 *
	 * @param type     the scan type
	 * @param apiLabel the integration the repositories belong to
	 * @param csv      the file, at most {@value #MAX_BYTES} bytes
	 * @param user     who imported, for the log
	 * @return how many repositories were updated, how many rows were skipped and why
	 * @throws IllegalArgumentException if the file is not a CSV with a repo column or has too
	 *                                  many rows
	 */
	@Transactional
	public ImportResult importCsv(ScanType type, String apiLabel, Reader csv, String user)
			throws IOException {
		List<CSVRecord> records = parse(csv);
        persistence.lockScope("ruleset-configuration");
		Map<String, Long> ids = repositoryIds(type, apiLabel);
		Map<String, Long> rulesetIds = new HashMap<>();
		for (RulesetDto ruleset : rulesets.getRulesets()) {
			if (ruleset.getDesignation() != RulesetDesignation.SUPPORTING) {
				rulesetIds.put(ruleset.getName().toLowerCase(Locale.ROOT), ruleset.getId());
			}
		}
		List<CsvUpdate> updates = new ArrayList<>();
		List<String> errors = new ArrayList<>();
		int skipped = 0;
		for (CSVRecord record : records) {
			try {
				updates.add(row(record, ids, rulesetIds));
			} catch (IllegalArgumentException e) {
				skipped++;
				if (errors.size() < MAX_ERRORS) {
					errors.add("Line " + (record.getRecordNumber() + 1) + ": " + e.getMessage());
				}
			}
		}
  // Lock in primary-key order before applying file order, including duplicate CSV rows.
  Map<Long,RepositoryEntity> locked=new HashMap<>();
  updates.stream().map(CsvUpdate::id).distinct().sorted().forEach(id->{
   var entity=persistence.lock(RepositoryEntity.class,id);
   if(entity==null)throw new IllegalArgumentException("Repository was removed; reload the inventory");locked.put(id,entity);
  });
  for(var update:updates){
   var entity=locked.get(update.id());
   if(update.updateTeam())entity.setTeam(update.team());
   if(update.updateOwner())entity.setOwnerName(update.owner());
   if(update.updateLabels())entity.setLabels(RepoLabels.split(update.labels()));
   if(update.criticality()!=null)entity.setCriticality(update.criticality());
   if(update.updateRuleset())entity.setRuleset(update.rulesetId()==null?null:persistence.find(RulesetEntity.class,update.rulesetId()));
  }
  persistence.flush();
		LOG.info("{} imported {} repositories of {} ({} rows skipped)", user, updates.size(),
				apiLabel, skipped);
		return new ImportResult(updates.size(), skipped, errors);
	}

	private static List<CSVRecord> parse(Reader csv) throws IOException {
		CSVFormat format = CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreHeaderCase()
				.withTrim().withIgnoreEmptyLines();
		try (CSVParser parser = format.parse(csv)) {
			if (parser.getHeaderMap().keySet().stream().noneMatch("repo"::equalsIgnoreCase)) {
				throw new IllegalArgumentException(
						"The first line must name the columns, including repo");
			}
			List<CSVRecord> records = new ArrayList<>();
			for (CSVRecord record : parser) {
				if (records.size() == MAX_ROWS) {
					throw new IllegalArgumentException(
							"A file can have at most " + MAX_ROWS + " rows");
				}
				records.add(record);
			}
			return records;
		} catch (IllegalStateException | UncheckedIOException e) {
			throw new IllegalArgumentException("The file is not a readable CSV");
		}
	}

	private Map<String, Long> repositoryIds(ScanType type, String apiLabel) {
		Map<String, Long> ids = new HashMap<>();
  for(var row:persistence.maps("SELECT r.id AS id,r.repoName AS name FROM RepositoryEntity r WHERE r.apiLabel=?1 AND r.scanType=?2",0,Integer.MAX_VALUE,apiLabel,type))ids.put(((String)row.get("name")).toLowerCase(Locale.ROOT),((Number)row.get("id")).longValue());
		return ids;
	}

	private static CsvUpdate row(CSVRecord record, Map<String, Long> ids,
			Map<String, Long> rulesetIds) {
		String name = value(record, "repo").orElse("");
		Long id = ids.get(name.toLowerCase(Locale.ROOT));
		if (id == null) {
			throw new IllegalArgumentException("no repository named "
					+ StringUtils.abbreviate(name, 80) + " in this integration");
		}
		String team = value(record, "team").orElse("");
		String owner = value(record, "owner").orElse("");
		if (team.length() > 128 || owner.length() > 255) {
			throw new IllegalArgumentException("team or owner is too long");
		}
		String labels = RepoLabels.format(RepoLabels.split(value(record, "labels").orElse("")));
		Integer criticality = value(record, "criticality").filter(StringUtils::isNotBlank)
				.map(RepositoryCsvService::criticality).orElse(null);
		Optional<String> ruleset = value(record, "ruleset").filter(StringUtils::isNotBlank);
		Long rulesetId = null;
		if (ruleset.isPresent() && !"none".equalsIgnoreCase(ruleset.get())) {
			rulesetId = rulesetIds.get(ruleset.get().toLowerCase(Locale.ROOT));
			if (rulesetId == null) {
				throw new IllegalArgumentException("no primary ruleset named "
						+ StringUtils.abbreviate(ruleset.get(), 80));
			}
		}
		return new CsvUpdate(id,flag(record,"team")==1,StringUtils.trimToNull(team),flag(record,"owner")==1,StringUtils.trimToNull(owner),flag(record,"labels")==1,labels,criticality,ruleset.isPresent(),rulesetId);
	}

	/** @return 1 if the file has the column, so the update sets it; 0 leaves it alone */
	private static int flag(CSVRecord record, String column) {
		return record.toMap().keySet().stream().anyMatch(column::equalsIgnoreCase) ? 1 : 0;
	}

	private static Integer criticality(String value) {
		for (RepoCriticality level : RepoCriticality.values()) {
			if (level.getDisplayName().equalsIgnoreCase(value)
					|| String.valueOf(level.getLevel()).equals(value)) {
				return level.getLevel();
			}
		}
		throw new IllegalArgumentException("criticality must be Critical, High, Normal or Low");
	}

	/**
	 * @return the cell of the column, any case; an export's formula guard (a leading ') is
	 *         dropped so an exported file imports unchanged
	 */
	private static Optional<String> value(CSVRecord record, String column) {
		for (Map.Entry<String, String> cell : record.toMap().entrySet()) {
			if (cell.getKey().equalsIgnoreCase(column)) {
				return Optional.ofNullable(cell.getValue()).map(String::trim)
						.map(RepositoryCsvService::dropFormulaGuard);
			}
		}
		return Optional.empty();
	}

	/**
	 * @return the value without the ' an export puts before a would-be formula; any other
	 *         leading ' is kept
	 */
	static String dropFormulaGuard(String value) {
		return value.length() > 1 && value.charAt(0) == '\''
				&& "=+-@\t\r".indexOf(value.charAt(1)) >= 0 ? value.substring(1) : value;
	}

	/**
	 * What an import did.
	 *
	 * @param updated repositories updated
	 * @param skipped rows not applied
	 * @param errors  why, for the first {@value RepositoryCsvService#MAX_ERRORS} skipped rows
	 */
	public record ImportResult(int updated, int skipped, List<String> errors) {
	}
}
