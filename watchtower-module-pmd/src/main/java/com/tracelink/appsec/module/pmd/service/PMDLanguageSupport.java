package com.tracelink.appsec.module.pmd.service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import net.sourceforge.pmd.lang.Language;
import net.sourceforge.pmd.lang.java.JavaLanguageModule;
import net.sourceforge.pmd.lang.scala.ScalaLanguageModule;
import net.sourceforge.pmd.lang.xml.XmlLanguageModule;

/**
 * Enumeration of the Watchtower-supported language types from PMD
 *
 * @author csmith
 *
 */
public enum PMDLanguageSupport {
	JAVA(JavaLanguageModule.getInstance()),
	SCALA(ScalaLanguageModule.getInstance()),
	XML(XmlLanguageModule.getInstance());

	private final String languageName;
	private final Language pmdLanguage;

	PMDLanguageSupport(Language pmdLanguage) {
		this.pmdLanguage = pmdLanguage;
		this.languageName = pmdLanguage.getName();
	}

	public String getLanguageName() {
		return languageName;
	}

	public Language getPMDLanguage() {
		return this.pmdLanguage;
	}


	@Override
	public String toString() {
		return languageName;
	}

	public static List<String> getSupportedLanguageNames() {
		return Arrays.stream(PMDLanguageSupport.values())
				.map(PMDLanguageSupport::toString)
				.collect(Collectors.toList());
	}

	public static Optional<PMDLanguageSupport> getPMDLanguageSupport(Language language) {
		return Arrays.stream(PMDLanguageSupport.values())
				.filter(langSupport -> langSupport.getPMDLanguage().getName()
						.equals(language.getName()))
				.findFirst();
	}

}
