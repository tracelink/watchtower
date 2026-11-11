package com.tracelink.appsec.watchtower.core.persistence;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** Guards the repository-wide persistence rule across existing and future application code. */
class PersistenceArchitectureTest {
 @Test void applicationCrudCannotBypassHibernate()throws Exception {
  Path root=Path.of("").toAbsolutePath();while(!Files.isDirectory(root.resolve("watchtower-core")))root=root.getParent();
  Pattern forbidden=Pattern.compile("JdbcTemplate|NamedParameterJdbcTemplate|createNativeQuery|nativeQuery\\s*=\\s*true|prepareStatement|createStatement|DriverManager\\.getConnection");
  List<String> violations=new ArrayList<>();
  try(var modules=Files.list(root)) {
   for(var module:modules.filter(path->path.getFileName().toString().startsWith("watchtower-")).toList()) {
    Path sources=module.resolve("src/main/java");if(!Files.isDirectory(sources))continue;
    try(var files=Files.walk(sources)) {
     for(var file:files.filter(path->path.toString().endsWith(".java")).toList()) {
      String relative=root.relativize(file).toString();
      // ShedLock owns its infrastructure statements; application CRUD has no exemptions.
      if(relative.equals("watchtower-core/src/main/java/com/tracelink/appsec/watchtower/core/configuration/SchedulerLockConfiguration.java"))continue;
      if(forbidden.matcher(Files.readString(file)).find())violations.add(relative);
     }
    }
   }
  }
  assertEquals(List.of(),violations,"Application data access must use typed Hibernate/JPA entities and repositories (AGENTS.md)");
 }
}
