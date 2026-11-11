package com.tracelink.appsec.watchtower.core.scan.repository;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetChoices;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetPageService;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService.Kind;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryCsvService.ImportResult;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Counts;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Row;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Tab;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService.RepoEdit;

/**
 * The repository inventory: the one place code (and image) repositories are managed. One tab
 * per integration, a status chip per repository, a search that takes the plan selector's tokens,
 * and bulk changes on the selected rows. Scanning starts from here; the scans themselves are on
 * /reposcan.
 *
 * @author csmith
 */
@Controller
@RequestMapping({"/repository", "/repositories"})
@PreAuthorize("hasAnyAuthority('" + CorePrivilege.REPO_SETTINGS_VIEW_NAME + "', '"
		+ CorePrivilege.SCAN_RESULTS_NAME + "')")
public class RepositoryController {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryController.class);

	private static final String REPOSITORY_UNAVAILABLE_MESSAGE =
			"Repository configuration is temporarily unavailable. Please try again.";

	static final int PAGE_SIZE = 50;

	/** The repository page's views: its pull requests, or its repository scans. */
	static final String PULL_REQUESTS = "pull-requests";

	static final String SCANS = "scans";
	static final String ALL = "all";

	private final RepositoryService repoService;

	private final RepositoryInventoryService inventory;

	private final RulesetPageService rulesetPages;

	private final RepoScanService scans;

	private final RepositoryCsvService csv;

	private final RepositoryPullRequestService pullRequests;
	private final CodeScanResultsService results;

	public RepositoryController(RepositoryService repoService,
			RepositoryInventoryService inventory, RulesetPageService rulesetPages,
			RepoScanService scans, RepositoryCsvService csv,
			RepositoryPullRequestService pullRequests, CodeScanResultsService results) {
		this.repoService = repoService;
		this.inventory = inventory;
		this.rulesetPages = rulesetPages;
		this.scans = scans;
		this.csv = csv;
		this.pullRequests = pullRequests;
		this.results = results;
	}

	/** The code repository inventory's readable URL; legacy scan-type URLs remain available. */
	@GetMapping
	public WatchtowerModelAndView codeRepositories(@RequestParam(defaultValue = "0") int page,
			@RequestParam(required = false) String source,
			@RequestParam(defaultValue = "") String q,
			@RequestParam(defaultValue = "") String status,
			@RequestParam(defaultValue = "") String label,
			@RequestParam(defaultValue = "") String scanned) {
		return repositoryScreen(CodeScanType.PULL_REQUEST.getTypeName(), page, source, q,
				status, label, scanned);
	}

	/**
	 * The inventory of one integration (tab), filtered and paged on the server.
	 */
	@GetMapping("/{scanType:[a-z_]+}")
	public WatchtowerModelAndView repositoryScreen(@PathVariable String scanType,
			@RequestParam(defaultValue = "0") int page,
			@RequestParam(required = false) String source,
			@RequestParam(defaultValue = "") String q,
			@RequestParam(defaultValue = "") String status,
			@RequestParam(defaultValue = "") String label,
			@RequestParam(defaultValue = "") String scanned) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/repository");
		Optional<ScanType> type = inventoryType(scanType);
		if (type.isEmpty()) {
			mav.setViewName("/");
			mav.addErrorMessage("Unknown repository scan type");
			return mav;
		}
		String query = StringUtils.left(q.trim(), RepositoryFilter.MAX_SEARCH);
		RepositoryFilter filter = RepositoryFilter.of(query, status, label, scanned);
		mav.addObject("activeScanType", scanType);
		mav.addObject("isCode", type.get() == CodeScanType.PULL_REQUEST);
		// A sync in progress is shown on the sync button, which is then off: a second request would only be refused.
		mav.addObject("syncRunning", type.get() == CodeScanType.PULL_REQUEST && scans.isSyncRunning());
		mav.addObject("inventoryPath", type.get() == CodeScanType.PULL_REQUEST
				? "/repositories" : "/repository/" + scanType);
		mav.addObject("pageTitle", type.get() == CodeScanType.PULL_REQUEST ? "Code repositories"
				: "Image repositories");
		mav.addObject("query", query);
		mav.addObject("filter", filter);
		mav.addObject("statuses", RepoStatus.values());
		try {
			List<Tab> tabs = inventory.tabs(type.get());
			mav.addObject("tabs", tabs);
			if (tabs.isEmpty()) {
				mav.addObject("rows", List.of());
				mav.addObject("rulesetChoices", RulesetChoices.EMPTY);
				return mav;
			}
			// Ignoring case, as the database (and so the tabs) does: a repository stored under
			// "bitbucket" links to the "Bitbucket" tab
			Tab active = tabs.stream().filter(t -> t.label().equalsIgnoreCase(source)).findFirst()
					.orElse(tabs.get(0));
			String baseUrl = inventoryUrl(scanType, active.label(), query, filter);
			Page<Row> rows = inventory.rows(type.get(), active.label(), filter,
					PageRequest.of(Math.max(page, 0), PAGE_SIZE, Sort.by("repoName")));
			if (page < 0 || (rows.getTotalPages() > 0 && page >= rows.getTotalPages())) {
				return redirect(baseUrl + "&page=" + Math.max(0, rows.getTotalPages() - 1));
			}
			Counts counts = inventory.counts(type.get(), active.label(),
					tabs.stream().anyMatch(Tab::orphaned));
			mav.addObject("activeSource", active.label());
			mav.addObject("activeOrphaned", active.orphaned());
			mav.addObject("counts", counts);
			mav.addObject("lastSync", inventory.ago(counts.lastSync()));
			mav.addObject("labels", inventory.labels(type.get(), active.label()));
			mav.addObject("rows", rows.getContent());
			mav.addObject("pagination", PagedResult.of(rows, r -> r));
			mav.addObject("baseUrl", baseUrl);
			mav.addObject("rulesetChoices", RulesetChoices.of(rulesetPages.summaries()));
			mav.addObject("criticalities", RepoCriticality.values());
			mav.addObject("frequencies", PlanFrequency.values());
		} catch (DataAccessException e) {
			LOG.error("Unable to load repository configuration for scan type {}", scanType, e);
			mav.addObject("tabs", List.of());
			mav.addObject("rows", List.of());
			mav.addObject("rulesetChoices", RulesetChoices.EMPTY);
			mav.addErrorMessage(REPOSITORY_UNAVAILABLE_MESSAGE);
		}
		mav.addScriptReference("/scripts/repo-scan.js");
		mav.addScriptReference("/scripts/ruleset-picker.js");
		mav.addScriptReference("/scripts/missed-case.js");
		mav.addScriptReference("/scripts/variant-search.js");
		return mav;
	}

	/**
	 * One repository: its status, facts and actions, then either its pull requests (the default)
	 * or its repository scans.
	 */
	@GetMapping("/{scanType}/{id:\\d+}")
	public WatchtowerModelAndView detail(@PathVariable String scanType, @PathVariable long id,
			@RequestParam(defaultValue = PULL_REQUESTS) String view,
			@RequestParam(defaultValue = "0") int page, Authentication authentication) {
		ScanType type = inventoryType(scanType)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		Row row = inventory.row(id).filter(r -> type.equals(r.repo().getScanType()))
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/repositorydetail");
		mav.addObject("row", row);
		mav.addObject("activeScanType", scanType);
		mav.addObject("isCode", type == CodeScanType.PULL_REQUEST);
		mav.addObject("inventoryPath", type == CodeScanType.PULL_REQUEST
				? "/repositories" : "/repository/" + scanType);
		mav.addObject("lastPr", lastPullRequest(type, row.repo()));
		mav.addObject("synced", inventory.ago(row.repo().getScmSyncedAt()));
		// The history links to scan reports, so it needs what they need
		boolean showHistory = type == CodeScanType.PULL_REQUEST && authentication != null
				&& authentication.getAuthorities().stream()
						.anyMatch(a -> CorePrivilege.SCAN_RESULTS_NAME.equals(a.getAuthority()));
		mav.addObject("showHistory", showHistory);
		if (showHistory) {
			addHistory(mav, id, row.repo(), view, page);
		}
		mav.addObject("rulesetChoices", RulesetChoices.of(rulesetPages.summaries()));
		mav.addObject("criticalities", RepoCriticality.values());
		mav.addObject("frequencies", PlanFrequency.values());
		mav.addScriptReference("/scripts/repo-scan.js");
		mav.addScriptReference("/scripts/ruleset-picker.js");
		mav.addScriptReference("/scripts/missed-case.js");
		mav.addScriptReference("/scripts/variant-search.js");
		return mav;
	}

	/** A code repository's combined history defaults to all individual scans. */
	@GetMapping("/{id:\\d+}")
	public WatchtowerModelAndView codeRepository(@PathVariable long id,
			@RequestParam(defaultValue = ALL) String view,
			@RequestParam(defaultValue = "0") int page, Authentication authentication) {
		return detail(CodeScanType.PULL_REQUEST.getTypeName(), id, view, page, authentication);
	}

	/**
	 * "#58 · Open · 7 d ago": the newest pull request with its state and when it was last
	 * reviewed, else the repository's own date (image repositories, or pull requests the catalog
	 * cannot match), else "never".
	 */
	private String lastPullRequest(ScanType type, RepositoryEntity repo) {
		if (type == CodeScanType.PULL_REQUEST) {
			try {
				var latest = pullRequests.latest(repo.getApiLabel(), repo.getRepoName());
				if (latest.isPresent()) {
					var pr = latest.get();
					String when = pr.getLastReviewedDate() > 0
							? " · " + inventory.ago(pr.getLastReviewedDate()) : "";
					return "#" + pr.getPrId() + " · " + pullRequestState(pr) + when;
				}
			} catch (DataAccessException e) {
				LOG.warn("Unable to read the latest pull request of repository {}", repo.getId(), e);
			}
		}
		return inventory.ago(repo.getLastReviewedDate());
	}

	private static String pullRequestState(
			com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository.PullRequestSummary pr) {
		if (!pr.isResolved()) {
			return "Open";
		}
		if (pr.getClosedState() == null) {
			return "Closed";
		}
		return switch (pr.getClosedState()) {
			case MERGED -> "Merged";
			case DECLINED -> "Declined";
			default -> "Closed";
		};
	}

	/**
	 * The page's history: the repository's pull requests (matched by integration and name) or
	 * its repository scans, one page of either.
	 */
	private void addHistory(WatchtowerModelAndView mav, long id, RepositoryEntity repo,
			String view, int page) {
		Kind kind = SCANS.equals(view) ? Kind.REPOSITORY
				: PULL_REQUESTS.equals(view) ? Kind.PR : Kind.ALL;
		String active = kind == Kind.REPOSITORY ? SCANS
				: kind == Kind.PR ? PULL_REQUESTS : ALL;
		mav.addObject("view", active);
		mav.addObject("baseUrl", "/repositories/"
				+ id + "?view=" + active);
		try {
			var history = results.page(kind, page, repo);
			mav.addObject("history", history.content());
			mav.addObject("pagination", history);
			mav.addObject("historyCounts", results.counts(repo));
		} catch (DataAccessException e) {
			LOG.error("Unable to load the {} of repository {}", active, id, e);
			mav.addObject("history", List.of());
			mav.addErrorMessage("This repository's history is temporarily unavailable. "
					+ "Please try again.");
		}
	}

	/**
	 * Lists every SCM integration's repositories again, through the queue.
	 */
	@PostMapping("/{scanType}/sync")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String sync(@PathVariable String scanType,
			@RequestParam(defaultValue = "") String source, Principal user,
			RedirectAttributes redirect) {
		if (inventoryType(scanType).orElse(null) != CodeScanType.PULL_REQUEST) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Only code repositories are synced");
		} else {
			int queued = scans.requestSync(user.getName()).size();
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION, queued == 0
					? "A repository sync is already running"
					: "Syncing the repository list; it updates here when done");
		}
		return backTo(scanType, source, "");
	}

	/**
	 * Deletes every repository of a deleted integration and their repository scans, so its tab
	 * goes away. Only a deleted integration's: a live one's come back at its next sync.
	 */
	@PostMapping("/{scanType}/clean-up")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String cleanUp(@PathVariable String scanType, @RequestParam String source,
			Principal user, RedirectAttributes redirect) {
		Optional<String> deleted = inventoryType(scanType).flatMap(type -> inventory.tabs(type)
				.stream().filter(Tab::orphaned).map(Tab::label).filter(source::equalsIgnoreCase)
				.findFirst());
		if (deleted.isEmpty()) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Only a deleted integration's repositories can be cleaned up");
			return backTo(scanType, source, "");
		}
		try {
			RepositoryService.DeleteResult result =
					inventory.deleteAllOf(deleted.get(), user.getName());
			LOG.info("{} cleaned up {} repositories of deleted integration {}", user.getName(),
					result.deleted(), deleted.get());
			if (result.busy() > 0) {
				redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Deleted " + plural(result.deleted()) + "; " + plural(result.busy())
								+ " being scanned left as is, so try again after their scans");
				return backTo(scanType, deleted.get(), "");
			}
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Deleted " + deleted.get() + " and its " + plural(result.deleted()));
		} catch (DataAccessException e) {
			LOG.error("Unable to clean up the repositories of {}", deleted.get(), e);
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Not all of them could be deleted. Please try again.");
			return backTo(scanType, deleted.get(), "");
		}
		return "redirect:" + inventoryPathFor(scanType);
	}

	/**
	 * A change to the selected repositories, or to every repository the page's filter matches
	 * ({@code matching=true}, resolved here and applied {@value RepositoryService#MAX_BULK} at a
	 * time): {@code edit} (rulesetId: absent keeps, -1 for none; team, owner, labels,
	 * criticality: blank keeps each repository's value), {@code pause}, {@code resume} or
	 * {@code delete}.
	 */
	@PostMapping("/{scanType}/bulk")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String bulk(@PathVariable String scanType, @RequestParam String action,
			@RequestParam(required = false) List<Long> repoIds,
			@RequestParam(defaultValue = "false") boolean matching,
			@RequestParam(required = false) Long rulesetId,
			@RequestParam(required = false) String team,
			@RequestParam(required = false) String owner,
			@RequestParam(required = false) String labels,
			@RequestParam(required = false) Integer criticality,
			@RequestParam(defaultValue = "") String source,
			@RequestParam(defaultValue = "") String q,
			@RequestParam(defaultValue = "") String status,
			@RequestParam(defaultValue = "") String label,
			@RequestParam(defaultValue = "") String scanned, Principal user,
			RedirectAttributes redirect) {
		RepositoryFilter filter = RepositoryFilter.of(q, status, label, scanned);
		Optional<ScanType> type = inventoryType(scanType);
		try {
			List<Long> ids = matching && type.isPresent()
					? repoService.matchingIds(type.get(), source, filter)
					: repoIds == null ? List.of() : repoIds;
			if (ids.isEmpty()) {
				throw new IllegalArgumentException("Choose at least one repository");
			}
			int changed = 0;
			int busy = 0;
			for (int from = 0; from < ids.size(); from += RepositoryService.MAX_BULK) {
				List<Long> chunk = ids.subList(from,
						Math.min(ids.size(), from + RepositoryService.MAX_BULK));
				switch (action) {
					// Blank keeps each repository's value: one dialog edits many repositories
					case "edit" -> changed += repoService.editMany(chunk, rulesetId,
							StringUtils.trimToNull(team), StringUtils.trimToNull(owner),
							StringUtils.isBlank(labels) ? null : RepoLabels.split(labels),
							criticality);
					case "pause" -> changed += repoService.setPaused(chunk, true);
					case "resume" -> changed += repoService.setPaused(chunk, false);
					case "delete" -> {
						RepositoryService.DeleteResult result =
								repoService.delete(chunk, user.getName());
						changed += result.deleted();
						busy += result.busy();
					}
					default -> throw new IllegalArgumentException("Unknown change");
				}
			}
			LOG.info("{} applied {} to {} repositories", user.getName(), action, changed);
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					("delete".equals(action) ? "Deleted " : "Updated ") + plural(changed)
							+ (busy > 0 ? "; " + plural(busy) + " being scanned left as is"
									: ""));
		} catch (RulesetNotFoundException | RulesetException | IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					StringUtils.defaultIfBlank(e.getMessage(), "Could not change them"));
		}
		return backTo(scanType, source, status);
	}

	/**
	 * Changes one repository from its edit dialog. The dialog always sends the scanning switch,
	 * so a missing {@code scanning} means it was switched off.
	 */
	@PostMapping("/{scanType}/{id:\\d+}")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String edit(@PathVariable String scanType, @PathVariable long id,
			@RequestParam(required = false) Long rulesetId,
			@RequestParam(required = false) String team,
			@RequestParam(required = false) String owner,
			@RequestParam(required = false) String labels,
			@RequestParam(required = false) Integer criticality,
			@RequestParam(required = false) String scanning,
			@RequestParam(defaultValue = "") String source,
			@RequestParam(defaultValue = "") String status,
			@RequestParam(defaultValue = "false") boolean toDetail, Principal user,
			RedirectAttributes redirect) {
		try {
			RepositoryEntity repo = repoService.update(id, new RepoEdit(rulesetId, team, owner,
					labels, criticality, scanning == null));
			LOG.info("{} edited repository {} of {}", user.getName(), repo.getRepoName(),
					repo.getApiLabel());
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Saved " + repo.getRepoName());
		} catch (RulesetNotFoundException | RulesetException | IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					StringUtils.defaultIfBlank(e.getMessage(), "Could not save it"));
		}
		return toDetail ? "redirect:" + detailPathFor(scanType, id)
				: backTo(scanType, source, status);
	}

	/**
	 * Adds a repository of a source code integration by its slug, before any pull request or
	 * sync has listed it.
	 */
	@PostMapping("/{scanType}/add")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String add(@PathVariable String scanType, @RequestParam String source,
			@RequestParam String slug, @RequestParam(required = false) Long rulesetId,
			@RequestParam(required = false) String team,
			@RequestParam(required = false) String owner,
			@RequestParam(required = false) String labels,
			@RequestParam(required = false) Integer criticality, Principal user,
			RedirectAttributes redirect) {
		try {
			if (inventoryType(scanType).orElse(null) != CodeScanType.PULL_REQUEST) {
				throw new IllegalArgumentException("Only code repositories are added by hand");
			}
			RepositoryEntity repo = repoService.addManually(source, slug, new RepoEdit(
					rulesetId, team, owner, labels, criticality, null));
			LOG.info("{} added repository {} of {}", user.getName(), repo.getRepoName(), source);
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Added " + repo.getRepoName());
			return "redirect:" + detailPathFor(scanType, repo.getId());
		} catch (RulesetNotFoundException | RulesetException | IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					StringUtils.defaultIfBlank(e.getMessage(), "Could not add it"));
			return backTo(scanType, source, "");
		}
	}

	/**
	 * The repositories the page's filter matches, as CSV.
	 */
	@GetMapping("/{scanType}/export")
	public void export(@PathVariable String scanType, @RequestParam String source,
			@RequestParam(defaultValue = "") String q,
			@RequestParam(defaultValue = "") String status,
			@RequestParam(defaultValue = "") String label,
			@RequestParam(defaultValue = "") String scanned, HttpServletResponse response)
			throws IOException {
		ScanType type = inventoryType(scanType)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		response.setContentType("text/csv");
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		response.setHeader("Content-Disposition", "attachment; filename=\"repositories-"
				+ source.replaceAll("[^A-Za-z0-9._-]", "_") + ".csv\"");
		csv.export(type, source, RepositoryFilter.of(StringUtils.left(q,
				RepositoryFilter.MAX_SEARCH), status, label, scanned), response.getWriter());
	}

	/**
	 * Sets team, owner, labels, criticality and ruleset from a CSV (repo, team, owner, labels,
	 * criticality[, ruleset]).
	 */
	@PostMapping("/{scanType}/import")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String importCsv(@PathVariable String scanType, @RequestParam String source,
			@RequestParam MultipartFile file, Principal user, RedirectAttributes redirect) {
		try {
			ScanType type = inventoryType(scanType)
					.orElseThrow(() -> new IllegalArgumentException("Unknown repository type"));
			if (file.isEmpty() || file.getSize() > RepositoryCsvService.MAX_BYTES) {
				throw new IllegalArgumentException("Choose a CSV file of at most 1 MB");
			}
			ImportResult result;
			try (Reader reader = new InputStreamReader(file.getInputStream(),
					StandardCharsets.UTF_8)) {
				result = csv.importCsv(type, source, reader, user.getName());
			}
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					result.updated() + " updated, " + result.skipped() + " skipped");
			if (!result.errors().isEmpty()) {
				redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
						String.join("; ", result.errors()));
			}
		} catch (IllegalArgumentException | IOException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e instanceof IOException ? "The file could not be read" : e.getMessage());
		}
		return backTo(scanType, source, "");
	}

	private static String plural(int count) {
		return count + (count == 1 ? " repository" : " repositories");
	}

	/**
	 * @return the scan types with an inventory: code (pull request) and image repositories
	 */
	static Optional<ScanType> inventoryType(String scanType) {
		if (CodeScanType.PULL_REQUEST.getTypeName().equals(scanType)) {
			return Optional.of(CodeScanType.PULL_REQUEST);
		}
		if (ImageScanType.CONTAINER.getTypeName().equals(scanType)) {
			return Optional.of(ImageScanType.CONTAINER);
		}
		return Optional.empty();
	}

	/**
	 * @return the scan type's own name when it has an inventory, else code repositories', so a
	 *         redirect never carries the request's path text
	 */
	static String knownType(String scanType) {
		return inventoryType(scanType).orElse(CodeScanType.PULL_REQUEST).getTypeName();
	}

	private static String inventoryPathFor(String scanType) {
		return CodeScanType.PULL_REQUEST.getTypeName().equals(knownType(scanType))
				? "/repositories" : "/repository/" + knownType(scanType);
	}

	private static String detailPathFor(String scanType, long id) {
		return inventoryPathFor(scanType) + "/" + id;
	}

	/**
	 * After a change, back to the inventory: built only from what the server knows (the type,
	 * the integration's stored name when the request named one, the status filter), never from
	 * the request's own text.
	 */
	private String backTo(String scanType, String source, String status) {
		UriComponentsBuilder url = UriComponentsBuilder.fromPath(inventoryPathFor(scanType));
		inventoryType(scanType).flatMap(type -> inventory.tabs(type).stream().map(Tab::label)
				.filter(label -> label.equalsIgnoreCase(source)).findFirst())
				.ifPresent(label -> url.queryParam("source", label));
		RepoStatus.fromKey(status).ifPresent(s -> url.queryParam("status", s.getKey()));
		return "redirect:" + url.encode().build().toUriString();
	}

	/**
	 * A redirect with an empty model: Spring would otherwise append every model attribute to the
	 * redirect URL as a query parameter.
	 */
	private static WatchtowerModelAndView redirect(String url) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/repository");
		mav.getModelMap().clear();
		mav.setViewName("redirect:" + url);
		return mav;
	}

	/**
	 * @return {@code /repository/{scanType}?source=...} with the filter, URL-encoded; always has
	 *         a query string so callers can append {@code &page=}
	 */
	static String inventoryUrl(String scanType, String source, String query,
			RepositoryFilter filter) {
		UriComponentsBuilder url = UriComponentsBuilder.fromPath(inventoryPathFor(scanType))
				.queryParam("source", source);
		if (StringUtils.isNotBlank(query)) {
			url.queryParam("q", query);
		}
		if (filter.status() != null) {
			url.queryParam("status", filter.status().getKey());
		}
		if (filter.label() != null && !StringUtils.containsIgnoreCase(query,
				"label:" + filter.label())) {
			url.queryParam("label", filter.label());
		}
		if (filter.coverage() != null) {
			url.queryParam("scanned", filter.coverage().getKey());
		}
		return url.encode().build().toUriString();
	}
}
