/* A secured PubSub peer for the interop tests, on open62541 built with
 * encryption. It publishes or subscribes to the dataset
 *
 *     Counter (Int32), Wave (Double)
 *
 * from publisher 2234, writer group 100, writer 62541, in UADP, signed or
 * signed and encrypted with keys given as hex (token 1).
 *
 *     open62541_pubsub_peer publish   URL KEYHEX BITS MODE SECONDS
 *     open62541_pubsub_peer subscribe URL KEYHEX BITS MODE SECONDS
 *
 * BITS is 128 or 256 (PubSub-Aes128-CTR or Aes256-CTR), MODE sign or
 * encrypt, KEYHEX the signing key, encrypting key and key nonce in a row.
 * The subscriber prints "value <counter> <wave>" once a second. */
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/server_pubsub.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define PUBLISHER_ID 2234
#define WRITER_GROUP 100
#define WRITER_ID 62541

static UA_NodeId counterNode, waveNode;
static UA_Int32 counter = 0;

static int unhex(const char *hex, UA_Byte *out, size_t len) {
  if(strlen(hex) != len * 2) return -1;
  for(size_t i = 0; i < len; i++) {
    unsigned v;
    if(sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
    out[i] = (UA_Byte)v;
  }
  return 0;
}

static void tick(UA_Server *server, void *data) {
  (void)data;
  counter++;
  UA_Variant v;
  UA_Int32 c = counter;
  UA_Variant_setScalar(&v, &c, &UA_TYPES[UA_TYPES_INT32]);
  UA_Server_writeValue(server, counterNode, v);
  UA_Double w = sin(counter / 10.0);
  UA_Variant_setScalar(&v, &w, &UA_TYPES[UA_TYPES_DOUBLE]);
  UA_Server_writeValue(server, waveNode, v);
}

static UA_NodeId addVariable(UA_Server *server, UA_UInt32 id, const char *name,
                             const UA_DataType *type) {
  UA_VariableAttributes attr = UA_VariableAttributes_default;
  attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)name);
  attr.dataType = type->typeId;
  UA_NodeId node = UA_NODEID_NUMERIC(1, id);
  UA_Server_addVariableNode(server, node, UA_NS0ID(OBJECTSFOLDER), UA_NS0ID(ORGANIZES),
                            UA_QUALIFIEDNAME(1, (char *)name), UA_NS0ID(BASEDATAVARIABLETYPE),
                            attr, NULL, NULL);
  return node;
}

static UA_Server *newServer(int bits) {
  /* PEER_DEBUG=1 says everything open62541 does. */
  UA_ServerConfig defaults;
  memset(&defaults, 0, sizeof(defaults));
  if(getenv("PEER_DEBUG")) defaults.logging = UA_Log_Stdout_new(UA_LOGLEVEL_DEBUG);
  UA_ServerConfig_setDefault(&defaults);
  UA_Server *server = UA_Server_newWithConfig(&defaults);
  UA_ServerConfig *config = UA_Server_getConfig(server);
  config->pubSubConfig.securityPolicies =
      (UA_PubSubSecurityPolicy *)UA_malloc(sizeof(UA_PubSubSecurityPolicy));
  config->pubSubConfig.securityPoliciesSize = 1;
  if(bits == 256)
    UA_PubSubSecurityPolicy_Aes256Ctr(config->pubSubConfig.securityPolicies, config->logging);
  else
    UA_PubSubSecurityPolicy_Aes128Ctr(config->pubSubConfig.securityPolicies, config->logging);
  return server;
}

static UA_NodeId addConnection(UA_Server *server, const char *url) {
  UA_NetworkAddressUrlDataType address = {UA_STRING_NULL, UA_STRING((char *)url)};
  UA_PubSubConnectionConfig config;
  memset(&config, 0, sizeof(config));
  config.name = UA_STRING("Connection");
  config.transportProfileUri =
      UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
  UA_Variant_setScalar(&config.address, &address, &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
  config.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
  config.publisherId.id.uint16 = PUBLISHER_ID;
  UA_NodeId connection;
  UA_Server_addPubSubConnection(server, &config, &connection);
  return connection;
}

static int publish(const char *url, UA_ByteString keys[3], int bits, UA_MessageSecurityMode mode,
                   int seconds) {
  UA_Server *server = newServer(bits);
  UA_ServerConfig *config = UA_Server_getConfig(server);
  counterNode = addVariable(server, 60001, "Counter", &UA_TYPES[UA_TYPES_INT32]);
  waveNode = addVariable(server, 60002, "Wave", &UA_TYPES[UA_TYPES_DOUBLE]);
  UA_NodeId connection = addConnection(server, url);

  UA_NodeId dataSet;
  UA_PublishedDataSetConfig pds;
  memset(&pds, 0, sizeof(pds));
  pds.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
  pds.name = UA_STRING("Dataset");
  UA_Server_addPublishedDataSet(server, &pds, &dataSet);

  const char *names[2] = {"Counter", "Wave"};
  UA_NodeId nodes[2] = {counterNode, waveNode};
  for(int i = 0; i < 2; i++) {
    UA_DataSetFieldConfig field;
    memset(&field, 0, sizeof(field));
    field.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    field.field.variable.fieldNameAlias = UA_STRING((char *)names[i]);
    field.field.variable.publishParameters.publishedVariable = nodes[i];
    field.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_Server_addDataSetField(server, dataSet, &field, NULL);
  }

  UA_WriterGroupConfig group;
  memset(&group, 0, sizeof(group));
  group.name = UA_STRING("Group");
  group.publishingInterval = 100;
  group.writerGroupId = WRITER_GROUP;
  group.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
  group.securityMode = mode;
  group.securityPolicy = &config->pubSubConfig.securityPolicies[0];
  group.messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED;
  group.messageSettings.content.decoded.type = &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE];
  UA_UadpWriterGroupMessageDataType *message = UA_UadpWriterGroupMessageDataType_new();
  message->networkMessageContentMask = (UA_UadpNetworkMessageContentMask)(
      UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID | UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER |
      UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID |
      UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER);
  group.messageSettings.content.decoded.data = message;
  UA_NodeId writerGroup;
  UA_Server_addWriterGroup(server, connection, &group, &writerGroup);
  UA_UadpWriterGroupMessageDataType_delete(message);
  UA_Server_setWriterGroupEncryptionKeys(server, writerGroup, 1, keys[0], keys[1], keys[2]);

  UA_DataSetWriterConfig writer;
  memset(&writer, 0, sizeof(writer));
  writer.name = UA_STRING("Writer");
  writer.dataSetWriterId = WRITER_ID;
  writer.keyFrameCount = 1;
  UA_Server_addDataSetWriter(server, writerGroup, dataSet, &writer, NULL);

  UA_Server_addRepeatedCallback(server, tick, NULL, 100, NULL);
  UA_Server_enableAllPubSubComponents(server);

  UA_Server_run_startup(server);
  time_t end = time(NULL) + seconds;
  while(time(NULL) < end) UA_Server_run_iterate(server, true);
  UA_Server_run_shutdown(server);
  UA_Server_delete(server);
  return 0;
}

static int subscribe(const char *url, UA_ByteString keys[3], int bits, UA_MessageSecurityMode mode,
                     int seconds) {
  UA_Server *server = newServer(bits);
  UA_ServerConfig *config = UA_Server_getConfig(server);
  UA_NodeId connection = addConnection(server, url);

  UA_ReaderGroupConfig group;
  memset(&group, 0, sizeof(group));
  group.name = UA_STRING("ReaderGroup");
  group.securityMode = mode;
  group.securityPolicy = &config->pubSubConfig.securityPolicies[0];
  UA_NodeId readerGroup;
  UA_Server_addReaderGroup(server, connection, &group, &readerGroup);
  UA_Server_setReaderGroupEncryptionKeys(server, readerGroup, 1, keys[0], keys[1], keys[2]);

  UA_DataSetReaderConfig reader;
  memset(&reader, 0, sizeof(reader));
  reader.name = UA_STRING("Reader");
  reader.publisherId.idType = UA_PUBLISHERIDTYPE_UINT16;
  reader.publisherId.id.uint16 = PUBLISHER_ID;
  reader.writerGroupId = WRITER_GROUP;
  reader.dataSetWriterId = WRITER_ID;
  UA_DataSetMetaDataType_init(&reader.dataSetMetaData);
  reader.dataSetMetaData.name = UA_STRING("Dataset");
  reader.dataSetMetaData.fieldsSize = 2;
  reader.dataSetMetaData.fields =
      (UA_FieldMetaData *)UA_Array_new(2, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
  const char *names[2] = {"Counter", "Wave"};
  const UA_DataType *types[2] = {&UA_TYPES[UA_TYPES_INT32], &UA_TYPES[UA_TYPES_DOUBLE]};
  UA_UInt32 builtin[2] = {UA_NS0ID_INT32, UA_NS0ID_DOUBLE};
  for(int i = 0; i < 2; i++) {
    UA_FieldMetaData_init(&reader.dataSetMetaData.fields[i]);
    UA_NodeId_copy(&types[i]->typeId, &reader.dataSetMetaData.fields[i].dataType);
    reader.dataSetMetaData.fields[i].builtInType = (UA_Byte)builtin[i];
    reader.dataSetMetaData.fields[i].name = UA_STRING((char *)names[i]);
    reader.dataSetMetaData.fields[i].valueRank = -1;
  }
  UA_NodeId readerId;
  UA_Server_addDataSetReader(server, readerGroup, &reader, &readerId);

  UA_NodeId targets[2];
  UA_FieldTargetDataType vars[2];
  for(int i = 0; i < 2; i++) {
    targets[i] = addVariable(server, 61001 + (UA_UInt32)i, names[i], types[i]);
    UA_FieldTargetDataType_init(&vars[i]);
    vars[i].attributeId = UA_ATTRIBUTEID_VALUE;
    vars[i].targetNodeId = targets[i];
  }
  UA_Server_DataSetReader_createTargetVariables(server, readerId, 2, vars);
  UA_Server_enableAllPubSubComponents(server);

  UA_Server_run_startup(server);
  time_t end = time(NULL) + seconds, last = 0;
  while(time(NULL) < end) {
    UA_Server_run_iterate(server, true);
    time_t now = time(NULL);
    if(now != last) {
      last = now;
      UA_Variant c, w;
      UA_Variant_init(&c);
      UA_Variant_init(&w);
      UA_Server_readValue(server, targets[0], &c);
      UA_Server_readValue(server, targets[1], &w);
      if(UA_Variant_hasScalarType(&c, &UA_TYPES[UA_TYPES_INT32]) &&
         UA_Variant_hasScalarType(&w, &UA_TYPES[UA_TYPES_DOUBLE]))
        printf("value %d %.6f\n", *(UA_Int32 *)c.data, *(UA_Double *)w.data);
      else
        printf("value none\n");
      fflush(stdout);
      UA_Variant_clear(&c);
      UA_Variant_clear(&w);
    }
  }
  UA_Server_run_shutdown(server);
  UA_Server_delete(server);
  return 0;
}

int main(int argc, char **argv) {
  if(argc != 7) {
    fprintf(stderr, "usage: %s publish|subscribe URL KEYHEX BITS sign|encrypt SECONDS\n", argv[0]);
    return 2;
  }
  int bits = atoi(argv[4]);
  if(bits != 128 && bits != 256) return 2;
  size_t encrypting = bits == 256 ? 32 : 16;
  UA_Byte material[32 + 32 + 4];
  if(unhex(argv[3], material, 32 + encrypting + 4) != 0) {
    fprintf(stderr, "bad key\n");
    return 2;
  }
  UA_ByteString keys[3] = {{32, material}, {encrypting, material + 32}, {4, material + 32 + encrypting}};
  UA_MessageSecurityMode mode = strcmp(argv[5], "sign") == 0 ? UA_MESSAGESECURITYMODE_SIGN
                                                             : UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
  int seconds = atoi(argv[6]);
  if(strcmp(argv[1], "publish") == 0) return publish(argv[2], keys, bits, mode, seconds);
  if(strcmp(argv[1], "subscribe") == 0) return subscribe(argv[2], keys, bits, mode, seconds);
  return 2;
}
