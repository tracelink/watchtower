package com.tracelink.appsec.module.pmd.service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import net.sourceforge.pmd.lang.Language;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.java.JavaLanguageModule;
import net.sourceforge.pmd.lang.scala.ScalaLanguageModule;
import net.sourceforge.pmd.lang.xml.XmlLanguageModule;

public enum PMDLanguageSupport {
	JAVA(JavaLanguageModule.NAME, JavaLanguageModule.TERSE_NAME),
	SCALA(ScalaLanguageModule.NAME, ScalaLanguageModule.TERSE_NAME),
	XML(XmlLanguageModule.NAME, XmlLanguageModule.TERSE_NAME);

	private final String languageName;
	private final Language pmdLanguage;

	private PMDLanguageSupport(String languageName, String terseName) {
		this.languageName = languageName;
		this.pmdLanguage = LanguageRegistry.findLanguageByTerseName(terseName);
	}

	public String getLanguageName() {
		return languageName;
	}

	public Language getPMDLanguage() {
		return this.pmdLanguage;
	}


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
