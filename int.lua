-- Wireshark dissector for INT local report
local proto_int_fixed = Proto.new("int", "INT fixed report")
local proto_int_drop_report = Proto.new("int-drop", "INT drop report")
local proto_int_local_report = Proto.new("int-local", "INT local report")

local version_string = {
  [0] = "0.5",
  [1] = "1.0",
  [2] = "2.0"
}
local nproto_string = {
  [0] = "Ethernet",
  [1] = "Telemetry Drop header, followed by Ethernet",
  [2] = "Telemetry Switch Local header, followed by Ethernet"
}

-- Fields for INT fixed report
local fix_report_fields = {
  ProtoField.uint8("int.version", "Version", base.DEC, version_string, 0xF0),
  ProtoField.uint8("int.nproto", "Next Protocol", base.DEC, nproto_string, 0x0F),
  ProtoField.uint8("int.d", "Drop flag", base.DEC, nil, 0x80),
  ProtoField.uint8("int.q", "Queue flag", base.DEC, nil, 0x40),
  ProtoField.uint8("int.f", "Flow flag", base.DEC, nil, 0x20),
  ProtoField.uint32("int.rsvd", "Reserved", base.DEC, nil, 0x1fffc0),
  ProtoField.uint8("int.hw_id", "HW ID", base.DEC, nil, 0x3f),
  ProtoField.uint32("int.seq_no", "Sequence number"),
  ProtoField.uint32("int.ig_tstamp", "Ingress timestamp(ns)")
}
local fix_report_fields_offset_len = {
  {0, 1},
  {0, 1},
  {1, 1},
  {1, 1},
  {1, 1},
  {1, 3},
  {3, 1},
  {4, 4},
  {8, 4}
}

-- Fields for drop report
local drop_report_fields = {
  ProtoField.uint32("int.switch_id", "Switch ID"),
  ProtoField.uint16("int.ig_port", "Ingress port"),
  ProtoField.uint16("int.eg_port", "Egress port"),
  ProtoField.uint8("int.queue_id", "Queue ID"),
  ProtoField.uint8("int.drop_reason", "Drop reason"),
  ProtoField.uint16("int.pad", "Pad")
}
local drop_report_fields_offset_len = {
  {0, 4},
  {4, 2},
  {6, 2},
  {8, 1},
  {9, 1},
  {10, 2}
}

local local_report_fields = {
  ProtoField.uint32("int.switch_id", "Switch ID"),
  ProtoField.uint16("int.ig_port", "Ingress port"),
  ProtoField.uint16("int.eg_port", "Egress port"),
  ProtoField.uint8("int.queue_id", "Queue ID"),
  ProtoField.uint32("int.queue_occupancy", "Queue occupancy", base.DEC, nil, 0x00ffffff),
  ProtoField.uint32("int.eg_tstamp", "Egress timestamp(ns)")
}
local local_report_fields_offset_len = {
  {0, 4},
  {4, 2},
  {6, 2},
  {8, 1},
  {8, 4},
  {12, 4}
}

-- Register fields to proto
proto_int_fixed.fields = fix_report_fields
proto_int_drop_report.fields = drop_report_fields
proto_int_local_report.fields = local_report_fields

function dissect_fixed_report(tvb, tree)
  local payload_tree = tree:add(proto_int_fixed, tvb(0, 12))
  for i, field in ipairs(fix_report_fields) do
    local off = fix_report_fields_offset_len[i][1]
    local len = fix_report_fields_offset_len[i][2]
    payload_tree:add(field, tvb(off, len))
  end
  local nproto = bit.band(tvb(0,1):uint(), 0x0f);
  local ig_tstamp = tvb(8,4):uint()
  return nproto, tvb(12):tvb(), ig_tstamp
end

function dissect_drop_report(tvb, tree)
  local payload_tree = tree:add(proto_int_drop_report, tvb(0, 12))
  for i, field in ipairs(drop_report_fields) do
    local off = drop_report_fields_offset_len[i][1]
    local len = drop_report_fields_offset_len[i][2]
    payload_tree:add(field, tvb(off, len))
  end
  return tvb(12):tvb()
end

function dissect_local_report(tvb, tree, ig_tstamp)
  local payload_tree = tree:add(proto_int_local_report, tvb(0, 16))
  for i, field in ipairs(local_report_fields) do
    local off = local_report_fields_offset_len[i][1]
    local len = local_report_fields_offset_len[i][2]
    payload_tree:add(field, tvb(off, len))
  end
  local eg_tstamp = tvb(12,4):uint()
  payload_tree:add(tvb(12,4), "Hop Latency: ", (eg_tstamp - ig_tstamp))
  return tvb(16):tvb()
end

-- The main dissector
function proto_int_fixed.dissector(tvb, pinfo, tree)
  pinfo.cols.protocol = "INT"
  local nproto, next_tvb, ig_tstamp = dissect_fixed_report(tvb, tree)

  if nproto == 1 then
    next_tvb = dissect_drop_report(next_tvb, tree)
  elseif nproto == 2 then
    next_tvb = dissect_local_report(next_tvb, tree, ig_tstamp)
  end

  -- The rast bytes are Ethernet, use builtin dissector
  local eth_dis = Dissector.get("eth_withoutfcs")
  eth_dis:call(next_tvb, pinfo, tree)
end

udp_table = DissectorTable.get("udp.port"):add(32766, proto_int_fixed)
