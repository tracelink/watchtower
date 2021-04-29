"use strict";

module.exports = {
	ruleset: {
		name: "ESLint Rules",
		description: "A collection of custom and core ESLint rules",
        customRules: {
            "my-no-eq-null": {
            	meta: {
            		type: "suggestion",
            		docs: {
            			description: "disallow 'null' comparisons without type-checking operators",
            			category: "Best Practices",
            			recommended: false,
            			url: "https://eslint.org/docs/rules/no-eq-null"
            		},
            		schema: [],
            		messages: {
            			unexpected: "Use '===' to compare with null."
            		}
            	},
            	create(context) {
            		return {
            			BinaryExpression(node) {
            				const badOperator = node.operator === "==" || node.operator === "!=";
            				if (node.right.type === "Literal" && node.right.raw === "null"
            						&& badOperator || node.left.type === "Literal"
            						&& node.left.raw === "null" && badOperator) {
            					context.report({ node, messageId: "unexpected" });
                        	}
                        }
                    };
                }
            },
            "my-no-extra-semi": {
                meta: {
                    type: "suggestion",
                    docs: {
                        description: "disallow unnecessary semicolons",
                        category: "Some Category",
                        recommended: true,
                        suggestion: true,
                        url: "https://www.example.com"
                    },
                    fixable: "code",
                    messages: {
                        unexpected: "Unnecessary semicolon."
                    },
                    deprecated: true,
                    replacedBy: ["other-rule"],
                    schema: []
                },
                create(context) {
                    const sourceCode = context.getSourceCode();
                    /**
                    * Reports an unnecessary semicolon error.
                    * @param {Node|Token} nodeOrToken A node or a token to be reported.
                    * @returns {void}
                    */
                    function report(nodeOrToken) {
                        context.report({
                            node: nodeOrToken,
                            messageId: "unexpected"
                        });
                    }

                    /**
                     * Checks for a part of a class body.
                     * This checks tokens from a specified token to a next MethodDefinition or the end of class body.
                     * @param {Token} firstToken The first token to check.
                     * @returns {void}
                     */
                    function checkForPartOfClassBody(firstToken) {
                        for (let token = firstToken;
                            token.type === "Punctuator" && !(token.value
                                === "}" && token.type === "Punctuator");
                            token = sourceCode.getTokenAfter(token)
                        ) {
                            if (token.value === ";" && token.type === "Punctuator") {
                                report(token);
                            }
                        }
                    }

                    return {

                        /**
                         * Reports this empty statement, except if the parent node is a loop.
                         * @param {Node} node A EmptyStatement node to be reported.
                         * @returns {void}
                         */
                        EmptyStatement(node) {
                            const parent = node.parent,
                                allowedParentTypes = [
                                    "ForStatement",
                                    "ForInStatement",
                                    "ForOfStatement",
                                    "WhileStatement",
                                    "DoWhileStatement",
                                    "IfStatement",
                                    "LabeledStatement",
                                    "WithStatement"
                                ];

                            if (allowedParentTypes.indexOf(parent.type) === -1) {
                                report(node);
                            }
                        },

                        /**
                         * Checks tokens from the head of this class body to the first MethodDefinition or the end of this class body.
                         * @param {Node} node A ClassBody node to check.
                         * @returns {void}
                         */
                        ClassBody(node) {
                            checkForPartOfClassBody(sourceCode.getFirstToken(node, 1)); // 0 is `{`.
                        },

                        /**
                         * Checks tokens from this MethodDefinition to the next MethodDefinition or the end of this class body.
                         * @param {Node} node A MethodDefinition node of the start point.
                         * @returns {void}
                         */
                        MethodDefinition(node) {
                            checkForPartOfClassBody(sourceCode.getTokenAfter(node));
                        }
                    };
                }
            }
        },
        priorities: {
            "my-no-eq-null": 4,
            "my-no-extra-semi": 5,
            "no-console": 4,
            "no-eval": 2
        }
    }
}
