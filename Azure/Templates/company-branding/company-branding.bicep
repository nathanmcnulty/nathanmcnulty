param workflows_company_branding_name string = 'company-branding'

resource workflows_company_branding_name_resource 'Microsoft.Logic/workflows@2017-07-01' = {
  name: workflows_company_branding_name
  location: 'westus2'
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        When_a_HTTP_request_is_received: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            method: 'POST'
            schema: {
              type: 'object'
              properties: {
                type: {
                  type: 'string'
                }
                attachments: {
                  type: 'array'
                  items: {
                    type: 'object'
                    properties: {
                      contentType: {
                        type: 'string'
                      }
                      content: {
                        type: 'object'
                        properties: {
                          type: {
                            type: 'string'
                          }
                          body: {
                            type: 'array'
                            items: {
                              type: 'object'
                              properties: {
                                type: {
                                  type: 'string'
                                }
                                text: {
                                  type: 'string'
                                }
                              }
                              required: [
                                'type'
                                'text'
                              ]
                            }
                          }
                          '$schema': {
                            type: 'string'
                          }
                          version: {
                            type: 'string'
                          }
                        }
                      }
                    }
                    required: [
                      'contentType'
                      'content'
                    ]
                  }
                }
                trash: {
                  type: 'string'
                }
              }
            }
          }
        }
      }
      actions: {
        Condition: {
          actions: {}
          runAfter: {
            Parse_JSON: [
              'Succeeded'
            ]
          }
          else: {
            actions: {}
          }
          expression: {
            and: [
              {
                endsWith: [
                  '@body(\'Parse_JSON\')?[\'Referer\']'
                  'login.microsoftonline.com/'
                ]
              }
            ]
          }
          type: 'If'
        }
        Parse_JSON: {
          runAfter: {}
          type: 'ParseJson'
          inputs: {
            content: '@triggerOutputs()?[\'headers\']'
            schema: {
              properties: {
                headers: {
                  properties: {
                    Accept: {
                      type: 'string'
                    }
                    'Accept-Encoding': {
                      type: 'string'
                    }
                    'Accept-Language': {
                      type: 'string'
                    }
                    'CLIENT-IP': {
                      type: 'string'
                    }
                    Cookie: {
                      type: 'string'
                    }
                    'DISGUISED-HOST': {
                      type: 'string'
                    }
                    Host: {
                      type: 'string'
                    }
                    'Max-Forwards': {
                      type: 'string'
                    }
                    Referer: {
                      type: 'string'
                    }
                    'Sec-Fetch-Dest': {
                      type: 'string'
                    }
                    'Sec-Fetch-Mode': {
                      type: 'string'
                    }
                    'Sec-Fetch-Site': {
                      type: 'string'
                    }
                    'User-Agent': {
                      type: 'string'
                    }
                    'WAS-DEFAULT-HOSTNAME': {
                      type: 'string'
                    }
                    'X-ARR-LOG-ID': {
                      type: 'string'
                    }
                    'X-ARR-SSL': {
                      type: 'string'
                    }
                    'X-AppService-Proto': {
                      type: 'string'
                    }
                    'X-Forwarded-For': {
                      type: 'string'
                    }
                    'X-Forwarded-Proto': {
                      type: 'string'
                    }
                    'X-Forwarded-TlsVersion': {
                      type: 'string'
                    }
                    'X-Original-URL': {
                      type: 'string'
                    }
                    'X-SITE-DEPLOYMENT-ID': {
                      type: 'string'
                    }
                    'X-WAWS-Unencoded-URL': {
                      type: 'string'
                    }
                    'sec-ch-ua': {
                      type: 'string'
                    }
                    'sec-ch-ua-mobile': {
                      type: 'string'
                    }
                    'sec-ch-ua-platform': {
                      type: 'string'
                    }
                  }
                  type: 'object'
                }
              }
              type: 'object'
            }
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {}
      }
    }
  }
}
