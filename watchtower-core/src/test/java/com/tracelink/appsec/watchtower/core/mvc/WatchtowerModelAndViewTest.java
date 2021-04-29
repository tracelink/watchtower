package com.tracelink.appsec.watchtower.core.mvc;

import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.thymeleaf.spring5.view.ThymeleafView;

public class WatchtowerModelAndViewTest {

    @SuppressWarnings("unchecked")
    @Test
    public void basicConfig() {
        String viewName = "viewName";
        WatchtowerModelAndView mav = new WatchtowerModelAndView(viewName);
        MatcherAssert.assertThat(mav.getViewName(), Matchers.is(WatchtowerModelAndView.DEFAULT_VIEW_TEMPLATE));
        MatcherAssert.assertThat(mav.getModel().get(WatchtowerModelAndView.CONTENT_VIEW_NAME), Matchers.is(viewName));
        Assertions.assertEquals(0, ((List<String>) mav.getModel().get("styles")).size());
        Assertions.assertEquals(0, ((List<String>) mav.getModel().get("scripts")).size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void basicStyleScript() {
        String viewName = "viewName";
        String style = "styleName";
        String script = "scriptName";

        WatchtowerModelAndView mav = new WatchtowerModelAndView(viewName);
        mav.addScriptReference(script);
        mav.addStyleReference(style);

        MatcherAssert.assertThat(mav.getViewName(), Matchers.is(WatchtowerModelAndView.DEFAULT_VIEW_TEMPLATE));
        MatcherAssert.assertThat(mav.getModel().get(WatchtowerModelAndView.CONTENT_VIEW_NAME), Matchers.is(viewName));
        Assertions.assertEquals(1, ((List<String>) mav.getModel().get("styles")).size());
        Assertions.assertEquals(style, ((List<String>) mav.getModel().get("styles")).get(0));

        Assertions.assertEquals(1, ((List<String>) mav.getModel().get("scripts")).size());
        Assertions.assertEquals(script, ((List<String>) mav.getModel().get("scripts")).get(0));
    }

    @Test
    public void basicOverrideName() {
        String viewName = "viewName";

        WatchtowerModelAndView mav = new WatchtowerModelAndView(viewName);
        mav.setViewName(viewName);

        MatcherAssert.assertThat(mav.getViewName(), Matchers.is(viewName));
        MatcherAssert.assertThat(mav.getModel().get(WatchtowerModelAndView.CONTENT_VIEW_NAME), Matchers.nullValue());
        MatcherAssert.assertThat(mav.getModel().get("styles"), Matchers.nullValue());
        MatcherAssert.assertThat(mav.getModel().get("scripts"), Matchers.nullValue());
    }

    @Test
    public void basicOverrideView() {
        String viewName = "viewName";

        WatchtowerModelAndView mav = new WatchtowerModelAndView(viewName);
        mav.setView(new ThymeleafView(viewName));

        MatcherAssert.assertThat(mav.getViewName(), Matchers.nullValue());
        MatcherAssert.assertThat(mav.getModel().get(WatchtowerModelAndView.CONTENT_VIEW_NAME), Matchers.nullValue());
        MatcherAssert.assertThat(mav.getModel().get("styles"), Matchers.nullValue());
        MatcherAssert.assertThat(mav.getModel().get("scripts"), Matchers.nullValue());
    }

}