package com.tracelink.appsec.watchtower.core.assistant;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.HandlerInterceptor;
import jakarta.servlet.http.*;

/** While chat is not ready, chat requests get 503 with the reason; /assistant/status always answers so the drawer can explain. */
@Configuration
public class AssistantWebConfiguration implements WebMvcConfigurer {
 private final AssistantSettingsService settings;
 public AssistantWebConfiguration(AssistantSettingsService settings){this.settings=settings;}
 @Override public void addInterceptors(InterceptorRegistry registry){registry.addInterceptor(new HandlerInterceptor(){
  @Override public boolean preHandle(HttpServletRequest req,HttpServletResponse res,Object handler)throws Exception {
   // An async redispatch only completes an already admitted stream; the stream itself rechecks access.
   if(req.getDispatcherType()==jakarta.servlet.DispatcherType.ASYNC)return true;
   if(settings.available())return true;
   var readiness=settings.readiness();
   res.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);res.setContentType("application/json");res.setCharacterEncoding("UTF-8");
   res.getWriter().write(AssistantState.mapper().writeValueAsString(java.util.Map.of("error",readiness==null?"Chat is not available.":readiness.message())));
   return false;
  }
 }).addPathPatterns("/assistant/**").excludePathPatterns("/assistant/status");}
}
