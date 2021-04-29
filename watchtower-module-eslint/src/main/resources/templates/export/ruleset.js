"use strict";

module.exports = {
	ruleset: {
		name: "{{name}}",
		description: "{{description}}",
		customRules: {
			{{#customRules}}
			"{{name}}": {
        		meta: {
        			{{#type}}
        			type: "{{type.value}}",
        			{{/type}}
        			docs: {
        				description: "{{{message}}}",
        				{{#category}}
        				category: "{{category}}",
        				{{/category}}
        				{{#recommended}}
        				recommended: {{recommended}},
        				{{/recommended}}
        				{{#suggestion}}
        				suggestion: {{suggestion}},
        				{{/suggestion}}
        				url: "{{externalUrl}}"
        			},
        			{{#fixable}}
        			fixable: "{{fixable.value}}",
        			{{/fixable}}
        			{{#messages.0}}
        			messages: {
        				{{#messages}}
        				{{key}}: "{{{value}}}"{{^-last}},{{/-last}}
        				{{/messages}}
        			},
        			{{/messages.0}}
        			{{#deprecated}}
        			deprecated: {{deprecated}},
        			{{/deprecated}}
        			{{#replacedBy}}
        			replacedBy: {{{replacedBy}}},
        			{{/replacedBy}}
        			{{#schema}}
        			schema: {{{schema}}}
        			{{/schema}}
        			{{^schema}}
        			schema: []
        			{{/schema}}
        		},
        		{{{createFunction}}}
        	}{{^-last}},{{/-last}}
        	{{/customRules}}
		},
		priorities: {
			{{#priorities}}
			"{{key}}": {{value.priority}}{{^-last}},{{/-last}}
			{{/priorities}}
		}
	}
}
