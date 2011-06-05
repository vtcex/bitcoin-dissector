#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-tcp.h"

#define BITCOIN_PORT 8333

/*
 * Minimum bitcoin identification header.
 * - Magic - 4 bytes
 * - Command - 12 bytes
 * - Payload length - 4 bytes
 */
#define BITCOIN_HEADER_LENGTH 4+12+4

static int proto_bitcoin = -1;
static dissector_handle_t dissector_handle;

static gint hf_bitcoin_magic = -1;
static gint hf_bitcoin_command = -1;
static gint hf_bitcoin_length = -1;
static gint hf_bitcoin_checksum = -1;

/* version message */
static gint hf_bitcoin_msg_version = -1;
static gint hf_msg_version_version = -1;
static gint hf_msg_version_services = -1;
static gint hf_msg_version_timestamp = -1;
static gint hf_msg_version_addr_me = -1;
static gint hf_msg_version_addr_you = -1;
static gint hf_msg_version_nonce = -1;
static gint hf_msg_version_subver = -1;
static gint hf_msg_version_start_height = -1;

/* addr message */
static gint hf_bitcoin_msg_addr = -1;
static gint hf_msg_addr_count = -1;
static gint hf_msg_addr_address = -1;
static gint hf_msg_addr_timestamp = -1;

/* services */
static gint hf_services_network = -1;

/* address */
static gint hf_address_services = -1;
static gint hf_address_address = -1;
static gint hf_address_port = -1;

static gint ett_bitcoin = -1;
static gint ett_bitcoin_msg = -1;
static gint ett_services = -1;
static gint ett_address = -1;
static gint ett_addr_list = -1;

static guint get_bitcoin_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 length = BITCOIN_HEADER_LENGTH;

  if(tvb_memeql(tvb, offset+4, "version", 7) != 0 &&
      tvb_memeql(tvb, offset+4, "verack", 6) != 0)
  {
    /* add checksum field */
    length += 4;
  }

  /* add payload length */
  return length + tvb_get_letohl(tvb, offset+16);
}

static proto_tree *create_services_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;
  guint64 services;

  tree = proto_item_add_subtree(ti, ett_services);

  /* start of services */
  /* NOTE:
   *  - 2011-06-05
   *    Currently the boolean tree only supports a maximum of 
   *    32 bits - so we split services in two
   */
  services = tvb_get_letoh64(tvb, offset);

  /* service = NODE_NETWORK */
  proto_tree_add_boolean(tree, hf_services_network, tvb, offset, 4, (guint32)services);

  /* end of services */

  return tree;
}

static proto_tree *create_address_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;

  tree = proto_item_add_subtree(ti, ett_address);

  /* services */
  ti = proto_tree_add_item(tree, hf_address_services, tvb, offset, 8, TRUE);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  /* IPv6 address */
  proto_tree_add_item(tree, hf_address_address, tvb, offset, 16, TRUE); 
  offset += 16;

  /* port */
  proto_tree_add_item(tree, hf_address_port, tvb, offset, 2, TRUE); 

  return tree;
}

static guint64 tvb_get_varint(tvbuff_t *tvb, const gint offset, gint *length)
{
  guint64 value;

  /* calculate variable length */
  value = tvb_get_guint8(tvb, offset);
  if(value < 0xfd)
  {
    *length = 1;
    return value;
  }

  if(value == 0xfd)
  {
    *length = 3;
    return tvb_get_letohs(tvb, offset+1);
  }
  else if(value == 0xfe)
  {
    *length = 5;
    return tvb_get_letohl(tvb, offset+1);
  }
  else
  {
    *length = 9;
    return tvb_get_letoh64(tvb, offset+1);
  }
}

static void dissect_bitcoin_msg_version(tvbuff_t *tvb, packet_info *pinfo, 
    proto_tree *tree, guint32 offset)
{
  proto_item *ti;
  gint subver_length;
  guint32 version;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_version, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  version = tvb_get_letohl(tvb, offset);

  proto_tree_add_item(tree, hf_msg_version_version, tvb, offset, 4, TRUE); 
  offset += 4;

  ti = proto_tree_add_item(tree, hf_msg_version_services, tvb, offset, 8, TRUE);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  proto_tree_add_item(tree, hf_msg_version_timestamp, tvb, offset, 8, TRUE); 
  offset += 8;

  ti = proto_tree_add_item(tree, hf_msg_version_addr_me, tvb, offset, 26, TRUE);
  create_address_tree(tvb, ti, offset);
  offset += 26;

  if(version >= 106)
  {
    ti = proto_tree_add_item(tree, hf_msg_version_addr_you, tvb, offset, 26, TRUE); 
    create_address_tree(tvb, ti, offset);
    offset += 26;

    proto_tree_add_item(tree, hf_msg_version_nonce, tvb, offset, 8, TRUE);
    offset += 8;

    /* find null terminated subver */
    subver_length = 0;
    subver_length = tvb_strsize(tvb, offset);
    proto_tree_add_item(tree, hf_msg_version_subver, tvb, offset, subver_length, TRUE);
    offset += subver_length;

    if(version >= 209)
    {
      proto_tree_add_item(tree, hf_msg_version_start_height, tvb, offset, 4, TRUE); 
      offset += 4;
    }
  }
}

static void dissect_bitcoin_msg_addr(tvbuff_t *tvb, packet_info *pinfo, 
    proto_tree *tree, guint32 offset)
{
  proto_item *ti;
  gint count_length;
  guint64 count;

  ti = proto_tree_add_item(tree, hf_bitcoin_msg_addr, tvb, offset, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);
  
  count = tvb_get_varint(tvb, offset, &count_length);
  proto_tree_add_text(tree, tvb, offset, count_length, 
      "Count: %llu", (long long unsigned int)count); 
  offset += count_length;

  for(; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, hf_msg_addr_address, tvb, offset, 30, FALSE);
    subtree = create_address_tree(tvb, ti, offset+4);

    proto_tree_add_item(subtree, hf_msg_addr_timestamp, tvb, offset, 4, TRUE);
    offset += 26;
    offset += 4;
  }
}


typedef void (*msg_dissector_func_t)(tvbuff_t *tvb, packet_info *pinfo, 
    proto_tree *tree, guint32 offset);

typedef struct msg_dissector
{ 
  const gchar *command;
  msg_dissector_func_t function;
} msg_dissector_t;

static msg_dissector_t msg_dissectors[] =
{
  {"version", dissect_bitcoin_msg_version},
  {"addr", dissect_bitcoin_msg_addr}
};

static void dissect_bitcoin_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  gchar *cmd;
  guint32 i;
  guint32 offset;

  offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bitcoin");

  ti = proto_tree_add_item(tree, proto_bitcoin, tvb, 0, -1, FALSE);
  tree = proto_item_add_subtree(ti, ett_bitcoin);

  cmd = tvb_get_string(tvb, 4, 12);
  col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", cmd);

  /* add basic protocol data */
  proto_tree_add_item(tree, hf_bitcoin_magic, tvb, 0, 4, FALSE);
  proto_tree_add_item(tree, hf_bitcoin_command, tvb, 4, 12, FALSE);
  proto_tree_add_item(tree, hf_bitcoin_length, tvb, 16, 4, TRUE);

  offset = 20;

  if(tvb_memeql(tvb, 4, "version", 7) != 0 &&
      tvb_memeql(tvb, 4, "verack", 6) != 0)
  {
    /* add checksum field */
    proto_tree_add_item(tree, hf_bitcoin_checksum, tvb, 20, 4, FALSE);
    offset += 4;

    /* TODO: verify checksum? */
  }

  /* handle command specific message part */
  for(i = 0; i < array_length(msg_dissectors); i++)
  {
    if(tvb_memeql(tvb, 4, msg_dissectors[i].command,
          strlen(msg_dissectors[i].command)) == 0)
    {
      msg_dissectors[i].function(tvb, pinfo, tree, offset);
    }
  }

  g_free(cmd);
}


static void dissect_bitcoin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, BITCOIN_HEADER_LENGTH, 
      get_bitcoin_pdu_length, dissect_bitcoin_tcp_pdu);
}

void proto_register_bitoin()
{
  static hf_register_info hf[] = {
    { &hf_bitcoin_magic,
      { "Packet magic", "bitcoin.magic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_bitcoin_command,
      { "Command name", "bitcoin.command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_bitcoin_length,
      { "Payload Length", "bitcoin.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bitcoin_checksum,
      { "Payload checksum", "bitcoin.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },

    /* version message */
    { &hf_bitcoin_msg_version,
      { "Version message", "bitcoin.version", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_version,
      { "Protocol version", "bitcoin.version.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_services,
      { "Node services", "bitcoin.version.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_version_addr_me,
      { "Address of emmitting node", "bitcoin.version.addr_me", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_version_addr_you,
      { "Address as seen by the emitting node", "bitcoin.version.addr_you", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_version_timestamp,
      { "Node timestamp", "bitcoin.version.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_nonce,
      { "Random nonce", "bitcoin.version.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_subver,
      { "Sub-version string", "bitcoin.version.subver", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_version_start_height,
      { "Block start height", "bitcoin.version.start_height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /* addr message */
    { &hf_bitcoin_msg_addr,
      { "Address message", "bitcoin.addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_msg_addr_address,
      { "Address", "bitcoin.addr.address", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_msg_addr_timestamp,
      { "Address timestamp", "bitcoin.addr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
    }, 


    /* services */
    { &hf_services_network,
      { "Network node", "bitcoin.services.network", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1, NULL, HFILL }
    }, 

    /* address */
    { &hf_address_services,
      { "Node services", "bitcoin.address.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_address_address,
      { "Node address", "bitcoin.address.address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }, 
    { &hf_address_port,
      { "Node port", "bitcoin.address.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    } 
  };

  static gint *ett[] = {
    &ett_bitcoin,
    &ett_bitcoin_msg,
    &ett_services,
    &ett_address,
    &ett_addr_list
  };

  proto_bitcoin = proto_register_protocol( "Bitcoin protocol", "Bitcoin",
      "bitcoin");

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_bitcoin, hf, array_length(hf));

  register_dissector("bitcoin.tcp", dissect_bitcoin, proto_bitcoin);

}

void proto_reg_handoff_bitcoin()
{
  dissector_handle = find_dissector("bitcoin.tcp");

  /* TODO: identify on magic */
  dissector_add_uint("tcp.port", BITCOIN_PORT, dissector_handle);
}

