package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The file types a scanner can analyse, and the checks that decide whether a scan has any.
 * <p>
 * A type is either an extension that starts with a dot ({@code .tf}, matched as a suffix of the
 * file name) or a file name pattern ({@code dockerfile*}, with {@code *} and {@code ?}). Types
 * match the file name only, never the folder, and ignore case. An empty list means every file.
 * <p>
 * The checks fail open: a directory that cannot be read counts as containing every type, so a
 * scanner is never skipped on the strength of a failed look.
 */
public final class ScannerFileTypes {
	/** Most types one scanner may list. */
	public static final int MAX_TYPES = 30;
	/** Longest single type. */
	public static final int MAX_TYPE_LENGTH = 64;
	/** Longest list as stored, comma separated; the module_settings column is 1000 characters. */
	public static final int MAX_STORED_LENGTH = 1000;

	private static final Pattern ALLOWED = Pattern.compile("[a-z0-9._*?-]+");

	private ScannerFileTypes() {
		// utility class
	}

	/**
	 * Cleans a list typed by a person: trims, lowercases, drops blanks and duplicates.
	 *
	 * @param raw the types as entered
	 * @return the cleaned types, in the order given
	 * @throws IllegalArgumentException if a type is a path, uses other characters, is too long, or
	 *                                  there are too many
	 */
	public static List<String> normalize(Collection<String> raw) {
		Set<String> cleaned = new LinkedHashSet<>();
		for (String entry : raw == null ? List.<String>of() : raw) {
			String type = entry == null ? "" : entry.trim().toLowerCase(Locale.ROOT);
			if (type.isEmpty()) {
				continue;
			}
			if (type.length() > MAX_TYPE_LENGTH || !ALLOWED.matcher(type).matches()) {
				throw new IllegalArgumentException(
						"Not a file type: " + entry + ". Use an extension such as .tf or a file name such as Dockerfile.");
			}
			cleaned.add(type.replaceAll("\\*+", "*"));
		}
		if (cleaned.size() > MAX_TYPES) {
			throw new IllegalArgumentException("Use at most " + MAX_TYPES + " file types.");
		}
		if (String.join(",", cleaned).length() > MAX_STORED_LENGTH) {
			throw new IllegalArgumentException("The list of file types is too long. Remove some or use shorter ones.");
		}
		return List.copyOf(cleaned);
	}

	/**
	 * @param type     one normalized type
	 * @param fileName a file name, without folders
	 * @return true if the file name is of this type
	 */
	public static boolean matches(String type, String fileName) {
		if (type == null || fileName == null) {
			return false;
		}
		String name = fileName.toLowerCase(Locale.ROOT);
		String wanted = type.toLowerCase(Locale.ROOT);
		if (wanted.startsWith(".")) {
			return name.endsWith(wanted);
		}
		return globMatches(wanted, name);
	}

	/**
	 * @param types a scanner's types; empty means every file
	 * @param paths file paths, with or without folders
	 * @return true if the scanner has something to look at among these paths
	 */
	public static boolean anyMatch(List<String> types, Collection<String> paths) {
		if (types.isEmpty()) {
			return true;
		}
		for (String path : paths) {
			if (path == null) {
				continue;
			}
			String name = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
			for (String type : types) {
				if (matches(type, name)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Looks through a directory once and reports which of the given types occur in it. Symbolic
	 * links are not followed. If the directory cannot be read, every type is reported present.
	 *
	 * @param root  the directory a scan was prepared in
	 * @param types the types to look for
	 * @return the subset of types that have at least one file under the root
	 */
	public static Set<String> matchedTypes(Path root, Collection<String> types) {
		Set<String> wanted = new LinkedHashSet<>(types);
		Set<String> found = new LinkedHashSet<>();
		if (wanted.isEmpty()) {
			return found;
		}
		boolean[] unreadable = {false};
		FileVisitor<Path> visitor = new SimpleFileVisitor<>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
				Path name = file.getFileName();
				if (name != null && attrs.isRegularFile()) {
					for (String type : wanted) {
						if (!found.contains(type) && matches(type, name.toString())) {
							found.add(type);
						}
					}
				}
				return found.size() == wanted.size() ? FileVisitResult.TERMINATE
						: FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult visitFileFailed(Path file, IOException exc) {
				// A folder or file that cannot be read may hold the very files we look for.
				unreadable[0] = true;
				return FileVisitResult.TERMINATE;
			}
		};
		try {
			if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
				return new LinkedHashSet<>(wanted);
			}
			Files.walkFileTree(root, Set.of(), Integer.MAX_VALUE, visitor);
		} catch (IOException | RuntimeException e) {
			return new LinkedHashSet<>(wanted);
		}
		return unreadable[0] ? new LinkedHashSet<>(wanted) : found;
	}

	/** A readable list for messages, such as ".tf, .yaml, dockerfile". */
	public static String describe(List<String> types) {
		return String.join(", ", new ArrayList<>(types));
	}

	/**
	 * Matches {@code *} (any run) and {@code ?} (one character) without regular expressions, so a
	 * hostile file name cannot make the match take exponential time: at most name x pattern steps.
	 */
	private static boolean globMatches(String glob, String name) {
		int g = 0;
		int n = 0;
		int starAt = -1;
		int resumeAt = 0;
		while (n < name.length()) {
			if (g < glob.length() && (glob.charAt(g) == '?' || glob.charAt(g) == name.charAt(n))) {
				g++;
				n++;
			} else if (g < glob.length() && glob.charAt(g) == '*') {
				starAt = g++;
				resumeAt = n;
			} else if (starAt >= 0) {
				g = starAt + 1;
				n = ++resumeAt;
			} else {
				return false;
			}
		}
		while (g < glob.length() && glob.charAt(g) == '*') {
			g++;
		}
		return g == glob.length();
	}
}
