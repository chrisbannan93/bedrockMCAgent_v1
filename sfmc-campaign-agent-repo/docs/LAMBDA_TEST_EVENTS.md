# Lambda event JSON samples

Each block below is an example Lambda event payload you can use for local testing.

## sfmc-asset-search

Source: `tools/sfmc-asset-search/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-asset-search",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-asset-search",
    "apiPath": "/searchAssets",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "queryText": "internet",
            "nameOperator": "contains"
          }
        }
      }
    }
  }
}
```

## sfmc-automation-inspector

Source: `tools/sfmc-automation-inspector/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-automation-inspector",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-automation-inspector",
    "apiPath": "/searchAutomations",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "queryText": "internet",
            "nameOperator": "contains",
            "page": 1,
            "pageSize": 10,
            "includeRaw": false
          }
        }
      }
    }
  }
}
```

## sfmc-blueprint-orchestrator

Source: `tools/sfmc-blueprint-orchestrator/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-blueprint-orchestrator",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-blueprint-orchestrator",
    "apiPath": "/generateBlueprint",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "campaignName": "Internet Plan Update",
            "brief": "Goal: announce new internet plans. Channel: email. Audience: residential subscribers. Offer: highlight faster speeds and flexible pricing. Timing: send once."
          }
        }
      }
    }
  }
}
```

## sfmc-brief-normalizer

Source: `tools/sfmc-brief-normalizer/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-brief-normalizer",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-brief-normalizer",
    "apiPath": "/normalizeBrief",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "rawBrief": "Send a reminder about scheduled internet maintenance this weekend.",
            "context": {
              "brand": "InternetCo"
            }
          }
        }
      }
    }
  }
}
```

## sfmc-category-path-inspector

Source: `tools/sfmc-category-path-inspector/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-category-path-inspector",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-category-path-inspector",
    "apiPath": "/getCategoryPath",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "categoryId": 10101,
            "limitRootCategoryId": 10000,
            "maxDepth": 5
          }
        }
      }
    }
  }
}
```

## sfmc-data-extension-creator

Source: `tools/sfmc-data-extension-creator/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-data-extension-creator",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-data-extension-creator",
    "apiPath": "/createDataExtension",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "name": "internet_subscribers",
            "customerKey": "internet_subscribers",
            "folderPath": "Generate_Via_AI_Agent/DataExtensions/Internet",
            "allowCreateMissingFolders": true,
            "dryRun": true,
            "fields": [
              {
                "name": "SubscriberKey",
                "type": "Text",
                "maxLength": 50,
                "isPrimaryKey": true
              },
              {
                "name": "EmailAddress",
                "type": "EmailAddress"
              },
              {
                "name": "PlanName",
                "type": "Text",
                "maxLength": 100
              },
              {
                "name": "SignupDate",
                "type": "Date"
              }
            ]
          }
        }
      }
    }
  }
}
```

## sfmc-data-extension-inspector

Source: `tools/sfmc-data-extension-inspector/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-data-extension-inspector",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-data-extension-inspector",
    "apiPath": "/inspectDataExtension",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "customerKey": "internet_subscribers",
            "includeFolderPath": true,
            "includeFields": true
          }
        }
      }
    }
  }
}
```

## sfmc-email-asset-writer

Source: `tools/sfmc-email-asset-writer/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "agent": {
    "name": "Jules",
    "id": "AGENT123",
    "alias": "JulesAlias",
    "version": "1"
  },
  "inputText": "Create an internet plan update email asset",
  "sessionId": "SESSION456",
  "actionGroup": "sfmc-email-asset-writer",
  "apiPath": "/writeEmailAsset",
  "httpMethod": "POST",
  "parameters": [],
  "requestBody": {
    "content": {
      "application/json": {
        "properties": [
          {
            "name": "categoryId",
            "type": "integer",
            "value": "12345"
          },
          {
            "name": "name",
            "type": "string",
            "value": "Internet Plan Update"
          },
          {
            "name": "subject",
            "type": "string",
            "value": "Your internet plan update"
          },
          {
            "name": "preheader",
            "type": "string",
            "value": "Faster speeds are here"
          },
          {
            "name": "htmlContent",
            "type": "string",
            "value": "<html><body><h1>Internet Plan Update</h1><p>Discover our latest internet options.</p></body></html>"
          }
        ]
      }
    }
  },
  "sessionAttributes": {},
  "promptSessionAttributes": {}
}
```

## sfmc-email-composer (KB RAG required)

Source: `tools/sfmc-email-composer/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "agent": {
    "name": "Jules",
    "id": "AGENT123",
    "alias": "JulesAlias",
    "version": "1"
  },
  "inputText": "Compose an email about new internet plans.",
  "sessionId": "SESSION456",
  "actionGroup": "sfmc-email-composer",
  "apiPath": "/composeEmail",
  "httpMethod": "POST",
  "parameters": [],
  "requestBody": {
    "content": {
      "application/json": {
        "properties": [
          {
            "name": "brand",
            "type": "string",
            "value": "InternetCo"
          },
          {
            "name": "brief",
            "type": "string",
            "value": "Draft a short email announcing faster internet plans."
          }
        ]
      }
    }
  },
  "sessionAttributes": {},
  "promptSessionAttributes": {}
}
```

## sfmc-health-inspector

Source: `tools/sfmc-health-inspector/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-health-inspector",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-health-inspector",
    "apiPath": "/healthreport",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "mode": "quick",
            "includeRestProbes": true,
            "includeSoapProbe": false
          }
        }
      }
    }
  }
}
```

## sfmc-journey-draft-builder

Source: `tools/sfmc-journey-draft-builder/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "actionGroup": "sfmc-journey-draft-builder",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-journey-draft-builder",
    "apiPath": "/journeydraft",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "body": {
            "createInSfmc": false,
            "dryRun": true,
            "journeySpec": {
              "key": "00000000-0000-0000-0000-000000000001",
              "name": "Internet Welcome Journey",
              "workflowApiVersion": 1,
              "triggers": [
                {
                  "type": "Event",
                  "key": "TRIGGER_1",
                  "name": "Internet Subscribers Entry",
                  "arguments": {}
                }
              ],
              "activities": [
                {
                  "type": "WAIT",
                  "name": "Wait 1 day",
                  "key": "WAIT_1",
                  "arguments": { "waitDuration": 1, "waitUnit": "DAYS" }
                }
              ]
            }
          }
        }
      }
    }
  }
}
```

## sfmc-journey-inspector

Source: `tools/sfmc-journey-inspector/tests/event-bedrock.json`

```json
{
  "messageVersion": "1.0",
  "agent": {
    "name": "Jules",
    "id": "AGENT123",
    "alias": "JulesAlias",
    "version": "1"
  },
  "inputText": "Search for journeys with 'internet' in the name",
  "sessionId": "SESSION456",
  "actionGroup": "sfmc-journey-inspector",
  "apiPath": "/searchJourneys",
  "httpMethod": "POST",
  "parameters": [],
  "requestBody": {
    "content": {
      "application/json": {
        "properties": [
          {
            "name": "nameOrDescription",
            "type": "string",
            "value": "internet"
          }
        ]
      }
    }
  },
  "sessionAttributes": {},
  "promptSessionAttributes": {}
}
```
