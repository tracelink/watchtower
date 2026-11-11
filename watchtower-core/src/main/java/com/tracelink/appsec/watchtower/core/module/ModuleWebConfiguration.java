package com.tracelink.appsec.watchtower.core.module;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.HandlerInterceptor;
import jakarta.servlet.http.*;

@Configuration
public class ModuleWebConfiguration implements WebMvcConfigurer {
 private final ModuleControlService controls;
 public ModuleWebConfiguration(ModuleControlService controls){this.controls=controls;}
 public void addInterceptors(InterceptorRegistry registry){registry.addInterceptor(new HandlerInterceptor(){
  public boolean preHandle(HttpServletRequest req,HttpServletResponse res,Object handler)throws Exception {
   String path=req.getRequestURI().substring(req.getContextPath().length());String[] segments=path.split("/");
   if(segments.length>2&&!controls.enabled(segments[2])){res.sendError(409,"Module disabled");return false;}return true;
  }
 }).addPathPatterns("/designer/*","/designer/*/**");}
}
