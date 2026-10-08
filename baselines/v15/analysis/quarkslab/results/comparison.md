# Decoder comparison summary

Generated mechanically from the paired Ghidra logs. Exact/interior xrefs are
candidate evidence only. Exhaustive-sweep results may include decoded data.

## Recursive phase

| Metric | Quarkslab | kagaimiq + patch |
|---|---:|---:|
| `instruction_count` | 51,089 | 1,893 |
| `instruction_bytes` | 149,332 | 4,618 |
| `undecoded_even_slots` | 103,510 | 175,867 |
| `function_count` | 1,055 | 133 |
| `call_instruction_count` | 4,430 | 198 |
| `direct_call_reference_count` | 4,214 | 184 |
| `branch_instruction_count` | 6,713 | 204 |
| `computed_flow_count` | 271 | 0 |
| `evidence_reference_count` | 479 | 0 |
| `evidence_scalar_count` | 98 | 6 |
| `evidence_pcode_constant_count` | 98 | 6 |
| decoded byte coverage | 41.906% | 1.296% |

## Exhaustive phase

| Metric | Quarkslab | kagaimiq + patch |
|---|---:|---:|
| `instruction_count` | 112,211 | 91,248 |
| `instruction_bytes` | 325,010 | 213,736 |
| `undecoded_even_slots` | 15,671 | 71,308 |
| `function_count` | 1,668 | 1,375 |
| `call_instruction_count` | 8,227 | 7,370 |
| `direct_call_reference_count` | 7,831 | 6,720 |
| `branch_instruction_count` | 14,786 | 10,679 |
| `computed_flow_count` | 725 | 552 |
| `evidence_reference_count` | 759 | 6 |
| `evidence_scalar_count` | 206 | 178 |
| `evidence_pcode_constant_count` | 206 | 178 |
| decoded byte coverage | 91.205% | 59.979% |

## Exact and interior target xrefs

| Phase | Target | Quarkslab exact/interior | kagaimiq + patch exact/interior |
|---|---|---:|---:|
| recursive | `midi_in_cs_endpoint` | 0/0 | 0/0 |
| recursive | `midi_in_endpoint` | 0/1 | 0/0 |
| recursive | `midi_jack_graph` | 0/2 | 0/0 |
| recursive | `midi_out_cs_endpoint` | 0/0 | 0/0 |
| recursive | `midi_out_endpoint` | 0/0 | 0/0 |
| recursive | `midi_product_utf16le` | 0/0 | 0/0 |
| recursive | `midi_route_ascii` | 0/0 | 0/0 |
| recursive | `midi_streaming_header` | 2/0 | 0/0 |
| recursive | `midi_streaming_interface` | 0/0 | 0/0 |
| recursive | `usb_device_descriptor` | 0/0 | 0/0 |
| recursive | `usb_midi_cin_payload_lengths` | 0/0 | 0/0 |
| exhaustive | `midi_in_cs_endpoint` | 0/0 | 0/0 |
| exhaustive | `midi_in_endpoint` | 0/2 | 0/0 |
| exhaustive | `midi_jack_graph` | 0/3 | 0/0 |
| exhaustive | `midi_out_cs_endpoint` | 0/0 | 0/0 |
| exhaustive | `midi_out_endpoint` | 0/0 | 0/0 |
| exhaustive | `midi_product_utf16le` | 0/0 | 0/0 |
| exhaustive | `midi_route_ascii` | 0/3 | 0/0 |
| exhaustive | `midi_streaming_header` | 2/0 | 0/0 |
| exhaustive | `midi_streaming_interface` | 0/0 | 0/0 |
| exhaustive | `usb_device_descriptor` | 0/0 | 0/0 |
| exhaustive | `usb_midi_cin_payload_lengths` | 0/1 | 0/0 |

## Decoder/tool error markers

| Marker | Quarkslab | kagaimiq + patch |
|---|---:|---:|
| `constant_propagation_exception` | 0 | 2 |
| `cross_build_error` | 2 | 0 |
| `delay_slot_context_error` | 357 | 0 |
| `pcode_error` | 1831 | 153 |
| `report_script_error` | 0 | 0 |
| `unresolved_constructor` | 394 | 153 |
