/*
 * An open62541 peer for yaopcua's interop tests, run in a process of its own.
 *
 *     open62541_peer server PORT [CERTIFICATE KEY TRUSTED...]
 *     open62541_peer client URL
 *     open62541_peer secure URL SERVER CLIENT CLIENT_KEY USER USER_KEY STRANGER STRANGER_KEY
 *
 * A server listens on PORT with the same nodes as asyncua_server.py, in ns=2: the object
 * Plant with Pump1.Speed (Int16 1500), Pump1.Running, Pump1.Name, Tank.Level,
 * Tank.Setpoints, Counter (counting up every 100 ms), the writable Scratch.* variables,
 * ReadOnly, the folder Many with 250 variables, and the methods Multiply (a * b) and
 * Fire (an event from the Server object). Anonymous users may connect, and so may the
 * user operator with the password secret. It prints "ready" once it listens, and stops
 * on SIGTERM.
 *
 * With a certificate and key, the server offers each security policy as well as None, to
 * clients with the trusted certificates, which may also log in with them.
 *
 * A client does what asyncua_client.py does, against the server that
 * server_interop_test.exs sets up, and prints one line for each thing it sees.
 *
 * A secure client connects to a secure server with each policy and mode, anonymously, as
 * operator and with the user certificate, writing 1700 to ns=2;s=Pump1.Speed and reading
 * it back, then once with the stranger's certificate. It prints one line for each:
 * "basic256sha256 sign anonymous 1700", or the status instead of the value.
 *
 * Certificates are DER files, and keys PEM; the server's names the application URI
 * urn:open62541.server.application, and the clients' urn:open62541.client.application. The secure modes need an open62541 built with
 * encryption, which Homebrew's isn't.
 */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_MBEDTLS)
#define SECURE
#endif

/* The application URIs the certificates must name. */
#define SERVER_URI "urn:open62541.server.application"
#define CLIENT_URI "urn:open62541.client.application"

static volatile UA_Boolean running = true;
static void stop(int signal) { running = false; }

/* Server */

static UA_UInt16 ns;
static UA_UInt32 counter = 0;

static void variable(UA_Server *server, const char *parent, const char *id, void *value,
                     const UA_DataType *type, size_t length, UA_Boolean writable) {
  UA_VariableAttributes attributes = UA_VariableAttributes_default;
  UA_UInt32 any_length = 0;
  if (length > 0) {
    UA_Variant_setArray(&attributes.value, value, length, type);
    attributes.valueRank = UA_VALUERANK_ONE_DIMENSION;
    attributes.arrayDimensions = &any_length;
    attributes.arrayDimensionsSize = 1;
  } else {
    UA_Variant_setScalar(&attributes.value, value, type);
  }
  attributes.dataType = type->typeId;
  attributes.displayName = UA_LOCALIZEDTEXT("en", (char *)id);
  attributes.accessLevel = UA_ACCESSLEVELMASK_READ | (writable ? UA_ACCESSLEVELMASK_WRITE : 0);

  UA_StatusCode status = UA_Server_addVariableNode(server, UA_NODEID_STRING(ns, (char *)id),
                            UA_NODEID_STRING(ns, (char *)parent),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                            UA_QUALIFIEDNAME(ns, (char *)id),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attributes,
                            NULL, NULL);
  if (status != UA_STATUSCODE_GOOD) fprintf(stderr, "%s: %s\n", id, UA_StatusCode_name(status));
}

static UA_Argument argument(const char *name, const UA_DataType *type) {
  UA_Argument argument;
  UA_Argument_init(&argument);
  argument.name = UA_STRING((char *)name);
  argument.dataType = type->typeId;
  argument.valueRank = UA_VALUERANK_SCALAR;
  return argument;
}

static void method(UA_Server *server, const char *id, UA_MethodCallback callback,
                   size_t inputs, const UA_Argument *input, size_t outputs,
                   const UA_Argument *output) {
  UA_MethodAttributes attributes = UA_MethodAttributes_default;
  attributes.displayName = UA_LOCALIZEDTEXT("en", (char *)id);
  attributes.executable = true;
  attributes.userExecutable = true;
  UA_Server_addMethodNode(server, UA_NODEID_STRING(ns, (char *)id), UA_NODEID_STRING(ns, "Plant"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                          UA_QUALIFIEDNAME(ns, (char *)id), attributes, callback, inputs, input,
                          outputs, output, NULL, NULL);
}

static UA_StatusCode multiply(UA_Server *server, const UA_NodeId *session, void *session_context,
                              const UA_NodeId *method, void *method_context,
                              const UA_NodeId *object, void *object_context, size_t inputs,
                              const UA_Variant *input, size_t outputs, UA_Variant *output) {
  UA_Int32 product = *(UA_Int32 *)input[0].data * *(UA_Int32 *)input[1].data;
  return UA_Variant_setScalarCopy(output, &product, &UA_TYPES[UA_TYPES_INT32]);
}

static UA_StatusCode fire(UA_Server *server, const UA_NodeId *session, void *session_context,
                          const UA_NodeId *method, void *method_context, const UA_NodeId *object,
                          void *object_context, size_t inputs, const UA_Variant *input,
                          size_t outputs, UA_Variant *output) {
  UA_LocalizedText message = {UA_STRING(""), *(UA_String *)input[0].data};
  return UA_Server_createEvent(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER),
                               UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE),
                               *(UA_UInt16 *)input[1].data, message, NULL, NULL, NULL);
}

static void tick(UA_Server *server, void *data) {
  counter++;
  UA_Variant value;
  UA_Variant_setScalar(&value, &counter, &UA_TYPES[UA_TYPES_UINT32]);
  UA_Server_writeValue(server, UA_NODEID_STRING(ns, "Counter"), value);
}

#ifdef SECURE
static UA_ByteString load(const char *path) {
  UA_ByteString bytes = UA_BYTESTRING_NULL;
  FILE *file = fopen(path, "rb");
  if (!file) {
    fprintf(stderr, "can't read %s\n", path);
    exit(2);
  }
  fseek(file, 0, SEEK_END);
  bytes.length = (size_t)ftell(file);
  bytes.data = UA_malloc(bytes.length + 1);
  fseek(file, 0, SEEK_SET);
  bytes.length = fread(bytes.data, 1, bytes.length, file);
  bytes.data[bytes.length] = 0;
  fclose(file);
  return bytes;
}
#endif

static int server(int port, int certificates, char **paths) {
  UA_ServerConfig config;
  memset(&config, 0, sizeof(config));
  config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);

  if (certificates == 0) {
    UA_ServerConfig_setMinimal(&config, (UA_UInt16)port, NULL);
  } else {
#ifdef SECURE
    UA_ByteString certificate = load(paths[0]), key = load(paths[1]);
    size_t trusted = (size_t)certificates - 2;
    UA_ByteString *trust = UA_calloc(trusted, sizeof(UA_ByteString));
    for (size_t i = 0; i < trusted; i++) trust[i] = load(paths[2 + i]);
    UA_ServerConfig_setDefaultWithSecurityPolicies(&config, (UA_UInt16)port, &certificate, &key,
                                                   trust, trusted, NULL, 0, NULL, 0);
    UA_String_clear(&config.applicationDescription.applicationUri);
    config.applicationDescription.applicationUri = UA_STRING_ALLOC(SERVER_URI);
#else
    fprintf(stderr, "open62541 is built without encryption\n");
    return 2;
#endif
  }

  /* Passwords in the clear are all None offers, and what these tests use. */
  UA_UsernamePasswordLogin login = {UA_STRING("operator"), UA_STRING("secret")};
  config.allowNonePolicyPassword = true;
  UA_AccessControl_default(&config, true, NULL, 1, &login);

  UA_Server *server = UA_Server_newWithConfig(&config);
  ns = UA_Server_addNamespace(server, "urn:open62541:test");

  UA_ObjectAttributes plant = UA_ObjectAttributes_default;
  plant.displayName = UA_LOCALIZEDTEXT("en", "Plant");
  UA_Server_addObjectNode(server, UA_NODEID_STRING(ns, "Plant"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(ns, "Plant"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE), plant, NULL, NULL);

  UA_Int16 speed = 1500, int16 = 0;
  UA_Boolean pump_running = true, boolean = true;
  UA_String name = UA_STRING("Pump 1"), string = UA_STRING("");
  UA_Double level = 2.5, setpoints[3] = {1.0, 2.0, 3.0}, scratch_double = 0.0, array[1] = {0.0};
  UA_UInt32 uint32 = 0;
  UA_Int32 read_only = 1;

  variable(server, "Plant", "Pump1.Speed", &speed, &UA_TYPES[UA_TYPES_INT16], 0, true);
  variable(server, "Plant", "Pump1.Running", &pump_running, &UA_TYPES[UA_TYPES_BOOLEAN], 0, true);
  variable(server, "Plant", "Pump1.Name", &name, &UA_TYPES[UA_TYPES_STRING], 0, true);
  variable(server, "Plant", "Tank.Level", &level, &UA_TYPES[UA_TYPES_DOUBLE], 0, true);
  variable(server, "Plant", "Tank.Setpoints", setpoints, &UA_TYPES[UA_TYPES_DOUBLE], 3, true);
  variable(server, "Plant", "Counter", &counter, &UA_TYPES[UA_TYPES_UINT32], 0, false);
  variable(server, "Plant", "Scratch.Int16", &int16, &UA_TYPES[UA_TYPES_INT16], 0, true);
  variable(server, "Plant", "Scratch.UInt32", &uint32, &UA_TYPES[UA_TYPES_UINT32], 0, true);
  variable(server, "Plant", "Scratch.Double", &scratch_double, &UA_TYPES[UA_TYPES_DOUBLE], 0, true);
  variable(server, "Plant", "Scratch.Boolean", &boolean, &UA_TYPES[UA_TYPES_BOOLEAN], 0, true);
  variable(server, "Plant", "Scratch.String", &string, &UA_TYPES[UA_TYPES_STRING], 0, true);
  variable(server, "Plant", "Scratch.Array", array, &UA_TYPES[UA_TYPES_DOUBLE], 1, true);
  variable(server, "Plant", "ReadOnly", &read_only, &UA_TYPES[UA_TYPES_INT32], 0, false);

  UA_ObjectAttributes many = UA_ObjectAttributes_default;
  many.displayName = UA_LOCALIZEDTEXT("en", "Many");
  UA_Server_addObjectNode(server, UA_NODEID_STRING(ns, "Many"), UA_NODEID_STRING(ns, "Plant"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(ns, "Many"),
                          UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE), many, NULL, NULL);
  for (UA_Int32 i = 0; i < 250; i++) {
    char id[16];
    snprintf(id, sizeof(id), "Item%d", (int)i);
    variable(server, "Many", id, &i, &UA_TYPES[UA_TYPES_INT32], 0, false);
  }

  UA_Argument factors[2] = {argument("a", &UA_TYPES[UA_TYPES_INT32]),
                            argument("b", &UA_TYPES[UA_TYPES_INT32])};
  UA_Argument product = argument("product", &UA_TYPES[UA_TYPES_INT32]);
  method(server, "Multiply", multiply, 2, factors, 1, &product);

  UA_Argument event[2] = {argument("message", &UA_TYPES[UA_TYPES_STRING]),
                          argument("severity", &UA_TYPES[UA_TYPES_UINT16])};
  method(server, "Fire", fire, 2, event, 0, NULL);

  UA_Server_addRepeatedCallback(server, tick, NULL, 100, NULL);

  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  UA_Server_run_startup(server);
  printf("ready\n");
  while (running) UA_Server_run_iterate(server, true);
  UA_Server_run_shutdown(server);
  UA_Server_delete(server);
  return 0;
}

/* Client */

static UA_Client *open_client(const char *url, const char *user, const char *password) {
  UA_ClientConfig config;
  memset(&config, 0, sizeof(config));
  config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);
  UA_ClientConfig_setDefault(&config);
  if (user) {
    config.allowNonePolicyPassword = true;
    UA_ClientConfig_setAuthenticationUsername(&config, user, password);
  }
  UA_Client *client = UA_Client_newWithConfig(&config);

  UA_StatusCode status = UA_Client_connect(client, url);
  if (status != UA_STATUSCODE_GOOD) {
    printf("connect %s\n", UA_StatusCode_name(status));
    exit(1);
  }

  return client;
}

static void close_client(UA_Client *client) {
  UA_Client_disconnect(client);
  UA_Client_delete(client);
}

static void spin(UA_Client *client, int ms) {
  for (int i = 0; i < ms / 10; i++) UA_Client_run_iterate(client, 10);
}

/* Prints a line: the name, then each element of the value, or the status if it's bad. */
static void print(const char *name, UA_StatusCode status, const UA_Variant *value) {
  if (status != UA_STATUSCODE_GOOD) {
    printf("%s %s\n", name, UA_StatusCode_name(status));
    return;
  }

  printf("%s", name);
  size_t n = UA_Variant_isScalar(value) ? 1 : value->arrayLength;
  for (size_t i = 0; i < n; i++) {
    void *at = (char *)value->data + i * value->type->memSize;
    if (value->type == &UA_TYPES[UA_TYPES_INT16]) {
      printf(" %d", *(UA_Int16 *)at);
    } else if (value->type == &UA_TYPES[UA_TYPES_INT32]) {
      printf(" %d", *(UA_Int32 *)at);
    } else if (value->type == &UA_TYPES[UA_TYPES_UINT16]) {
      printf(" %u", *(UA_UInt16 *)at);
    } else if (value->type == &UA_TYPES[UA_TYPES_DOUBLE]) {
      printf(" %g", *(UA_Double *)at);
    } else if (value->type == &UA_TYPES[UA_TYPES_BOOLEAN]) {
      printf(" %s", *(UA_Boolean *)at ? "true" : "false");
    } else if (value->type == &UA_TYPES[UA_TYPES_STRING]) {
      UA_String *s = at;
      printf(" %.*s", (int)s->length, s->data);
    } else if (value->type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) {
      UA_String *s = &((UA_LocalizedText *)at)->text;
      printf(" %.*s", (int)s->length, s->data);
    } else if (value->type == &UA_TYPES[UA_TYPES_NODEID]) {
      UA_String s = UA_STRING_NULL;
      UA_NodeId_print(at, &s);
      printf(" %.*s", (int)s.length, s.data);
      UA_String_clear(&s);
    } else {
      printf(" <%s>", value->type->typeName);
    }
  }
  printf("\n");
}

static void read_value(UA_Client *client, const char *name, UA_NodeId node) {
  UA_Variant value;
  UA_Variant_init(&value);
  print(name, UA_Client_readValueAttribute(client, node, &value), &value);
  UA_Variant_clear(&value);
}

static UA_StatusCode write_int16(UA_Client *client, UA_NodeId node, UA_Int16 int16) {
  UA_Variant value;
  UA_Variant_setScalar(&value, &int16, &UA_TYPES[UA_TYPES_INT16]);
  return UA_Client_writeValueAttribute(client, node, &value);
}

/* Counts a node's children, printing their browse names if asked, following continuation
 * points. */
static size_t browse(UA_Client *client, UA_NodeId node, UA_Boolean print_names) {
  UA_BrowseDescription description;
  UA_BrowseDescription_init(&description);
  description.nodeId = node;
  description.browseDirection = UA_BROWSEDIRECTION_FORWARD;
  description.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
  description.includeSubtypes = true;
  description.resultMask = UA_BROWSERESULTMASK_BROWSENAME;

  UA_BrowseRequest request;
  UA_BrowseRequest_init(&request);
  request.nodesToBrowse = &description;
  request.nodesToBrowseSize = 1;
  UA_BrowseResponse response = UA_Client_Service_browse(client, request);
  if (response.resultsSize != 1) return 0;

  size_t count = 0;
  UA_BrowseResult *result = &response.results[0];
  for (;;) {
    for (size_t i = 0; i < result->referencesSize; i++, count++) {
      UA_String *name = &result->references[i].browseName.name;
      if (print_names) printf(" %.*s", (int)name->length, name->data);
    }
    if (result->continuationPoint.length == 0) break;

    UA_BrowseNextRequest next;
    UA_BrowseNextRequest_init(&next);
    next.continuationPoints = &result->continuationPoint;
    next.continuationPointsSize = 1;
    UA_BrowseNextResponse more = UA_Client_Service_browseNext(client, next);
    UA_BrowseResult_clear(result);
    if (more.resultsSize != 1) {
      UA_BrowseNextResponse_clear(&more);
      break;
    }
    UA_BrowseResult_copy(&more.results[0], result);
    UA_BrowseNextResponse_clear(&more);
  }

  UA_BrowseResponse_clear(&response);
  return count;
}

static void path(UA_Client *client) {
  UA_RelativePathElement elements[2];
  const char *names[2] = {"Pump1", "Speed"};
  for (int i = 0; i < 2; i++) {
    UA_RelativePathElement_init(&elements[i]);
    elements[i].referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    elements[i].includeSubtypes = true;
    elements[i].targetName = UA_QUALIFIEDNAME(2, (char *)names[i]);
  }

  UA_BrowsePath browse_path;
  UA_BrowsePath_init(&browse_path);
  browse_path.startingNode = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
  browse_path.relativePath.elements = elements;
  browse_path.relativePath.elementsSize = 2;

  UA_TranslateBrowsePathsToNodeIdsRequest request;
  UA_TranslateBrowsePathsToNodeIdsRequest_init(&request);
  request.browsePaths = &browse_path;
  request.browsePathsSize = 1;
  UA_TranslateBrowsePathsToNodeIdsResponse response =
      UA_Client_Service_translateBrowsePathsToNodeIds(client, request);

  if (response.resultsSize == 1 && response.results[0].targetsSize == 1) {
    UA_Variant target;
    UA_Variant_setScalar(&target, &response.results[0].targets[0].targetId.nodeId,
                         &UA_TYPES[UA_TYPES_NODEID]);
    print("path", UA_STATUSCODE_GOOD, &target);
  } else {
    printf("path %s\n", UA_StatusCode_name(response.responseHeader.serviceResult));
  }
  UA_TranslateBrowsePathsToNodeIdsResponse_clear(&response);
}

static void call(UA_Client *client) {
  UA_Variant args[2];
  UA_Int32 a = 6, b = 7;
  UA_Variant_setScalar(&args[0], &a, &UA_TYPES[UA_TYPES_INT32]);
  UA_Variant_setScalar(&args[1], &b, &UA_TYPES[UA_TYPES_INT32]);
  size_t outputs = 0;
  UA_Variant *output = NULL;
  UA_StatusCode status = UA_Client_call(client, UA_NODEID_STRING(2, "Pump1"),
                                        UA_NODEID_STRING(2, "Pump1.Multiply"), 2, args,
                                        &outputs, &output);
  if (status == UA_STATUSCODE_GOOD && outputs != 1) status = UA_STATUSCODE_BADUNEXPECTEDERROR;
  print("multiply", status, output);
  UA_Array_delete(output, outputs, &UA_TYPES[UA_TYPES_VARIANT]);
}

/* A subscription: the current value, then a change this client makes. */

static UA_Int16 changes[8];
static size_t changed = 0;

static void data_change(UA_Client *client, UA_UInt32 sub, void *sub_context, UA_UInt32 item,
                        void *item_context, UA_DataValue *value) {
  if (changed < 8 && value->hasValue && value->value.type == &UA_TYPES[UA_TYPES_INT16])
    changes[changed++] = *(UA_Int16 *)value->value.data;
}

static void subscribe(const char *url) {
  UA_Client *client = open_client(url, NULL, NULL);
  UA_NodeId speed = UA_NODEID_STRING(2, "Pump1.Speed");

  UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
  request.requestedPublishingInterval = 50;
  UA_CreateSubscriptionResponse sub =
      UA_Client_Subscriptions_create(client, request, NULL, NULL, NULL);
  UA_MonitoredItemCreateRequest item = UA_MonitoredItemCreateRequest_default(speed);
  item.requestedParameters.samplingInterval = 50;
  UA_MonitoredItemCreateResult created = UA_Client_MonitoredItems_createDataChange(
      client, sub.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, item, NULL, data_change, NULL);
  if (created.statusCode != UA_STATUSCODE_GOOD)
    printf("subscription %s\n", UA_StatusCode_name(created.statusCode));

  spin(client, 300);
  write_int16(client, speed, 777);
  spin(client, 300);
  UA_Client_Subscriptions_deleteSingle(client, sub.subscriptionId);

  printf("subscription");
  for (size_t i = 0; i < changed; i++) printf(" %d", changes[i]);
  printf("\n");
  close_client(client);
}

/* An alarm: tripped through a method, then acknowledged by this client. An event's fields
 * come in the order they're selected. */

enum { CONDITION, EVENT_ID, MESSAGE, SEVERITY, ACTIVE, ACKED, COMMENT, FIELDS };
static const char *field_names[FIELDS][2] = {
    {NULL, NULL}, {"EventId", NULL}, {"Message", NULL}, {"Severity", NULL},
    {"ActiveState", "Id"}, {"AckedState", "Id"}, {"Comment", NULL}};
static UA_Variant events[8][FIELDS];
static size_t evented = 0;

static void event(UA_Client *client, UA_UInt32 sub, void *sub_context, UA_UInt32 item,
                  void *item_context, const UA_KeyValueMap fields) {
  if (evented == 8 || fields.mapSize != FIELDS) return;
  for (size_t i = 0; i < FIELDS; i++) UA_Variant_copy(&fields.map[i].value, &events[evented][i]);
  evented++;
}

static void alarms(const char *url) {
  UA_Client *client = open_client(url, NULL, NULL);

  UA_SimpleAttributeOperand clauses[FIELDS];
  UA_QualifiedName paths[FIELDS][2];
  for (size_t i = 0; i < FIELDS; i++) {
    UA_SimpleAttributeOperand_init(&clauses[i]);
    if (i == CONDITION) {
      /* The condition's own node id */
      clauses[i].typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
      clauses[i].attributeId = UA_ATTRIBUTEID_NODEID;
      continue;
    }
    clauses[i].typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
    clauses[i].attributeId = UA_ATTRIBUTEID_VALUE;
    clauses[i].browsePath = paths[i];
    for (size_t j = 0; j < 2 && field_names[i][j]; j++) {
      paths[i][j] = UA_QUALIFIEDNAME(0, (char *)field_names[i][j]);
      clauses[i].browsePathSize = j + 1;
    }
  }

  UA_EventFilter filter;
  UA_EventFilter_init(&filter);
  filter.selectClauses = clauses;
  filter.selectClausesSize = FIELDS;

  UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
  request.requestedPublishingInterval = 50;
  UA_CreateSubscriptionResponse sub =
      UA_Client_Subscriptions_create(client, request, NULL, NULL, NULL);

  UA_MonitoredItemCreateRequest item;
  UA_MonitoredItemCreateRequest_init(&item);
  item.itemToMonitor.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
  item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
  item.monitoringMode = UA_MONITORINGMODE_REPORTING;
  item.requestedParameters.queueSize = 10;
  item.requestedParameters.discardOldest = true;
  UA_ExtensionObject_setValue(&item.requestedParameters.filter, &filter,
                              &UA_TYPES[UA_TYPES_EVENTFILTER]);
  UA_MonitoredItemCreateResult created = UA_Client_MonitoredItems_createEvent(
      client, sub.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, item, NULL, event, NULL);
  if (created.statusCode != UA_STATUSCODE_GOOD)
    printf("alarm %s\n", UA_StatusCode_name(created.statusCode));

  size_t outputs = 0;
  UA_Variant *output = NULL;
  UA_StatusCode status = UA_Client_call(client, UA_NODEID_STRING(2, "Pump1"),
                                        UA_NODEID_STRING(2, "Pump1.Trip"), 0, NULL, &outputs,
                                        &output);
  if (status != UA_STATUSCODE_GOOD) printf("trip %s\n", UA_StatusCode_name(status));
  spin(client, 300);

  if (evented > 0) {
    UA_Variant *alarm = events[evented - 1];
    print("alarm_condition", UA_STATUSCODE_GOOD, &alarm[CONDITION]);
    print("alarm_message", UA_STATUSCODE_GOOD, &alarm[MESSAGE]);
    print("alarm_severity", UA_STATUSCODE_GOOD, &alarm[SEVERITY]);
    print("alarm_active", UA_STATUSCODE_GOOD, &alarm[ACTIVE]);
    print("alarm_acked", UA_STATUSCODE_GOOD, &alarm[ACKED]);

    UA_Variant args[2];
    UA_LocalizedText comment = UA_LOCALIZEDTEXT("", "from open62541");
    args[0] = alarm[EVENT_ID];
    UA_Variant_setScalar(&args[1], &comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    status = UA_Client_call(client, *(UA_NodeId *)alarm[CONDITION].data,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE),
                            2, args, &outputs, &output);
    if (status != UA_STATUSCODE_GOOD) printf("acknowledge %s\n", UA_StatusCode_name(status));
    spin(client, 300);

    UA_Variant *acked = events[evented - 1];
    print("alarm_acked_after", UA_STATUSCODE_GOOD, &acked[ACKED]);
    print("alarm_comment", UA_STATUSCODE_GOOD, &acked[COMMENT]);
  } else {
    printf("alarm none\n");
  }

  UA_Client_Subscriptions_deleteSingle(client, sub.subscriptionId);
  close_client(client);
}

static int client(const char *url) {
  UA_Client *client = open_client(url, NULL, NULL);

  read_value(client, "namespaces", UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_NAMESPACEARRAY));
  printf("objects");
  browse(client, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), true);
  printf("\n");

  UA_NodeId speed = UA_NODEID_STRING(2, "Pump1.Speed");
  read_value(client, "speed", speed);
  UA_StatusCode status = write_int16(client, speed, 1234);
  if (status != UA_STATUSCODE_GOOD) printf("write %s\n", UA_StatusCode_name(status));
  read_value(client, "speed_after", speed);

  UA_Variant value;
  UA_LocalizedText display;
  status = UA_Client_readDisplayNameAttribute(client, speed, &display);
  UA_Variant_setScalar(&value, &display, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
  print("display_name", status, &value);
  if (status == UA_STATUSCODE_GOOD) UA_LocalizedText_clear(&display);

  UA_NodeId data_type;
  status = UA_Client_readDataTypeAttribute(client, speed, &data_type);
  UA_Variant_setScalar(&value, &data_type, &UA_TYPES[UA_TYPES_NODEID]);
  print("data_type", status, &value);

  read_value(client, "levels", UA_NODEID_STRING(2, "Tank.Levels"));

  UA_Double temperature = 1.0;
  UA_Variant_setScalar(&value, &temperature, &UA_TYPES[UA_TYPES_DOUBLE]);
  status = UA_Client_writeValueAttribute(client, UA_NODEID_STRING(2, "Pump1.Temp"), &value);
  printf("read_only %s\n", UA_StatusCode_name(status));

  call(client);
  path(client);

  /* The server's state, from its status: 0 is Running. */
  read_value(client, "state", UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_STATE));
  printf("many %zu\n", browse(client, UA_NODEID_STRING(2, "Many"), false));
  close_client(client);

  subscribe(url);
  alarms(url);

  client = open_client(url, "operator", "secret");
  read_value(client, "user_read", UA_NODEID_STRING(2, "Pump1.Temp"));
  close_client(client);
  return 0;
}

#ifdef SECURE

/* Secure clients */

static const char *policies[][2] = {
    {"basic256sha256", "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"},
    {"aes128_sha256_rsa_oaep", "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"},
    {"aes256_sha256_rsa_pss", "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"}};

/* Connects with a policy and mode, as anonymous, operator or the user certificate, writes
 * and reads back, and prints the result. */
static void attempt(const char *url, const char *policy, const char *uri,
                    UA_MessageSecurityMode mode, const char *login, UA_ByteString server_cert,
                    UA_ByteString cert, UA_ByteString key, UA_ByteString user, UA_ByteString user_key) {
  UA_ClientConfig config;
  memset(&config, 0, sizeof(config));
  config.logging = UA_Log_Stdout_new(UA_LOGLEVEL_FATAL);
  UA_ClientConfig_setDefault(&config);
  UA_ClientConfig_setDefaultEncryption(&config, cert, key, &server_cert, 1, NULL, 0);
  UA_String_clear(&config.clientDescription.applicationUri);
  config.clientDescription.applicationUri = UA_STRING_ALLOC(CLIENT_URI);
  config.securityPolicyUri = UA_STRING_ALLOC(uri);
  config.securityMode = mode;
  if (strcmp(login, "password") == 0)
    UA_ClientConfig_setAuthenticationUsername(&config, "operator", "secret");
  else if (strcmp(login, "certificate") == 0)
    UA_ClientConfig_setAuthenticationCert(&config, user, user_key);

  UA_Client *client = UA_Client_newWithConfig(&config);
  printf("%s %s %s", policy, mode == UA_MESSAGESECURITYMODE_SIGN ? "sign" : "sign_and_encrypt",
         login);
  UA_StatusCode status = UA_Client_connect(client, url);
  if (status == UA_STATUSCODE_GOOD) {
    UA_NodeId speed = UA_NODEID_STRING(2, "Pump1.Speed");
    status = write_int16(client, speed, 1700);
    if (status == UA_STATUSCODE_GOOD) read_value(client, "", speed);
  }
  if (status != UA_STATUSCODE_GOOD) printf(" %s\n", UA_StatusCode_name(status));
  close_client(client);
}

static int secure(const char *url, char **paths) {
  UA_ByteString server_cert = load(paths[0]), cert = load(paths[1]), key = load(paths[2]),
                user = load(paths[3]), user_key = load(paths[4]), stranger = load(paths[5]),
                stranger_key = load(paths[6]);
  const char *logins[] = {"anonymous", "password", "certificate"};
  UA_MessageSecurityMode modes[] = {UA_MESSAGESECURITYMODE_SIGN,
                                    UA_MESSAGESECURITYMODE_SIGNANDENCRYPT};

  for (int p = 0; p < 3; p++)
    for (int m = 0; m < 2; m++)
      for (int l = 0; l < 3; l++)
        attempt(url, policies[p][0], policies[p][1], modes[m], logins[l], server_cert, cert,
                key, user, user_key);

  printf("untrusted ");
  fflush(stdout);
  attempt(url, policies[0][0], policies[0][1], UA_MESSAGESECURITYMODE_SIGNANDENCRYPT,
          "anonymous", server_cert, stranger, stranger_key, user, user_key);
  return 0;
}

#endif

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);

  if (argc >= 3 && strcmp(argv[1], "server") == 0) return server(atoi(argv[2]), argc - 3, argv + 3);
  if (argc == 3 && strcmp(argv[1], "client") == 0) return client(argv[2]);
#ifdef SECURE
  if (argc == 10 && strcmp(argv[1], "secure") == 0) return secure(argv[2], argv + 3);
#endif

  fprintf(stderr, "usage: open62541_peer server PORT [CERTIFICATE KEY TRUSTED...] | client URL"
                  " | secure URL SERVER CLIENT CLIENT_KEY USER USER_KEY STRANGER STRANGER_KEY\n");
  return 2;
}
