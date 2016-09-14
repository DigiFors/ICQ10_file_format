"""
Copyright (c) 2016 DigiFors GmbH, Leipzig

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR 
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE.
"""

import struct
import sqlite3
import os
import json
import argparse

# reads the contacts (plain JSON, so it's easy)
def read_contacts(filename):
  with open(filename, "rb") as f:
    return {"data": json.load(f)}

# reads a field in the info file. Checks magic number, gets field length and field content
def read_field(number, content, offset):
  number_input = struct.unpack("<I", content[offset:offset+0x04])[0]
  field_len = struct.unpack("<I", content[offset+0x04:offset+0x08])[0]
  field = content[offset+0x08:offset+0x08+field_len]
  if number_input != number:
    field = None
  return offset+0x08+field_len, field

def read_info(filename):
  with open(filename, "rb") as f:
    block_length_input = f.read(0x08)
    block_length = struct.unpack("<II", block_length_input)
    if block_length[0] != block_length[1]:
      return {"error": "Invalid block length in info file"}
    block = f.read(block_length[0])
    
    offset, no = read_field(1, block, 0) # ICQ#
    offset, _ = read_field(2, block, offset) # ICQ# again? not returned
    offset, name = read_field(3, block, offset) 
    offset, status = read_field(4, block, offset) 
    offset, acc_type = read_field(5, block, offset) # ICQ/AIM
    _, phone_no = read_field(6, block, offset) # with country prefix, without +
    return {"data": {"no": no, "name": name, "status": status, 
                     "acc_type": acc_type, "phone_no": phone_no}}


# Checks values in data against specified magic values
def check_magic(data, start, end, values):
  magic = struct.unpack("<" + "I"*len(values), data[start:end])
  if magic != values:
    return False
  else:
    return True

# Reads the _db2 files which contain chat messages, files, contact add/remove and calls
def read_db2(filename):
  with open(filename, "rb") as f:
    data = {"data": []}
    block_counter = 0
    while True:
      message = {"type": "message", "name": None, "message": None}
      block_counter += 1
      block_length_input = f.read(0x08)
      if len(block_length_input) == 0:
        return data
      block_length = struct.unpack("<II", block_length_input)
      if block_length[0] != block_length[1]:
        return {"error": "Invalid block length in block %s" % block_counter}
      block = f.read(block_length[0])
      block_length_input_2 = f.read(0x08)
      block_length_2 = struct.unpack("<II", block_length_input_2)
      if block_length_2[0] != block_length[0] or block_length_2[1] != block_length[0]:
        return {"error": "Invalid block length in block %s" % block_counter}
      if not check_magic(block, 0x00, 0x08, (0x01, 0x08)):
        return {"error": "Invalid magic values in block %s" % block_counter}
      message["timestamp_server"] = struct.unpack("<I", block[0x0c:0x10])[0]
      if not check_magic(block, 0x10, 0x18, (0x0d, 0x08)):
        return {"error": "Invalid magic values in block %s" % block_counter}
      if not check_magic(block, 0x20, 0x28, (0x02, 0x04)):
        return {"error": "Invalid magic values in block %s" % block_counter}
      direction = struct.unpack("<I", block[0x28:0x2c])[0]
      if direction == 0x00:
        message["direction"] = "incoming"
      elif direction == 0x04:
        message["direction"] = "outgoing"
      if not check_magic(block, 0x2c, 0x34, (0x03, 0x08)):
        return {"error": "Invalid magic values in block %s" % block_counter}
      message["timestamp_client"] = struct.unpack("<I", block[0x34:0x38])[0]
      if not check_magic(block, 0x38, 0x40, (0x00, 0x04)):
        return {"error": "Invalid magic values in block %s" % block_counter}
      if not check_magic(block, 0x40, 0x48, (0x00, 0x0e)):
        len_guid = struct.unpack("<I", block[0x40:0x44])[0]
        lgwm = len_guid
      else:
        len_guid = struct.unpack("<I", block[0x48:0x4c])[0]
        if len_guid != 0: # we do not care about the GUID, we just want the offset
          lgwm = len_guid + 0x08 # for the extra two magic bytes
        else:
          lgwm = 0
        
      
      if check_magic(block, 0x44+lgwm, 0x44+lgwm+0x04, (0x0e, )):
        is_name = True # name follows
      elif check_magic(block, 0x44+lgwm, 0x44+lgwm+0x04, (0x15, )):
        is_name = False
      else:
        return {"error": "Invalid magic values in block %s" % block_counter}
      len_guid_2 = struct.unpack("<I", block[0x44+lgwm+0x04:0x44+lgwm+0x08])[0]
      lgwm += len_guid_2 # again, just the offset
      
      if not check_magic(block, 0x44+lgwm+0x08, 0x44+lgwm+0x0c, (0x15, )) and \
         not check_magic(block, 0x44+lgwm+0x08, 0x44+lgwm+0x0c, (0x05, )):
        return {"error": "Invalid magic values in block %s" % block_counter}
      if is_name:
        
        name_len = struct.unpack("<I", block[0x44+lgwm+0x0c:0x44+lgwm+0x10])[0]
        if name_len != 0:
          message["name"] = block[0x44+lgwm+0x10:0x44+lgwm+0x10+name_len]
        if not check_magic(block, 0x44+lgwm+0x10+name_len, 0x44+lgwm+0x10+name_len+0x04, (0x05, )):
          return {"error": "Invalid magic values in block %s" % block_counter}
        new_offset = 0x44+lgwm+0x10+name_len+0x04
        
      else:
        new_offset = 0x44+lgwm+0x0c

      len_message = struct.unpack("<I", block[new_offset:new_offset+0x04])[0]
      if len_message != 0:
        message["message"] = block[new_offset+0x04:new_offset+0x04+len_message]
      if message["message"] is not None and message["message"].startswith("https://files.icq.net/get/"):
        message["type"] = "file"
      
      if len(block) > new_offset+0x04+len_message:
        new_offset += 0x04+len_message
        if check_magic(block, new_offset+0x10, new_offset+0x14, (0x02, )):
          message["type"] = "add_remove_contact"
        elif check_magic(block, new_offset+0x10, new_offset+0x14, (0x04, )):
          message["type"] = "start_call"
        elif check_magic(block, new_offset+0x10, new_offset+0x14, (0x03, )):
          message["type"] = "end_call"
      data["data"].append(message)
      
  return data


def write_sqlite_files(inputdir, outputdir):
  profiles = []
  for profile in range(1, 10000):
    if os.path.isdir(os.path.join(inputdir, str(profile).zfill(4))):
      profiles.append(os.path.join(inputdir, str(profile).zfill(4)))
    else:
      break
  if len(profiles) == 0:
    print "No profile found"
    return
  for profile in profiles:
    if os.path.exists(os.path.join(outputdir, "%s.db" % profile[-4:])):
      os.remove(os.path.join(outputdir, "%s.db" % profile[-4:]))
    conn = sqlite3.connect(os.path.join(outputdir, "%s.db" % profile[-4:]))
    conn.text_factory = str # we read bytes
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE basic_info (icq_number integer, name text, "
                   "status text, account_type text, phone_number text);")
    basic_info = read_info(os.path.join(os.path.join(profile, "info"), "cache"))
    if "error" in basic_info.keys():
      print "Error while reading basic info from %s: %s" % (os.path.join(os.path.join(profile, "info"), "cache"), basic_info["error"])
      continue
    cursor.execute("INSERT INTO basic_info VALUES (?, ?, ?, ?, ?);", 
                   (basic_info["data"]["no"], basic_info["data"]["name"], 
                    basic_info["data"]["status"], basic_info["data"]["acc_type"], 
                    basic_info["data"]["phone_no"]))
    cursor.execute("CREATE TABLE contact_groups (id integer, name text);")
    cursor.execute("CREATE TABLE contacts (icq_number integer, name text, "
                   "status text, status_msg text, account_type text, "
                   "last_seen integer, mute integer, group_id integer);")
    contacts = read_contacts(os.path.join(os.path.join(profile, "contacts"), "cache.cl"))
    if "error" in contacts.keys():
      print "Error while reading contacts from %s: %s" % (os.path.join(os.path.join(profile, "contacts"), 
                                                          "cache.cl"), contacts["error"])
      continue
    for group in contacts["data"]["groups"]:
      cursor.execute("INSERT INTO contact_groups VALUES (?, ?);", 
                     (group["id"], group["name"]))
      for contact in group["buddies"]:
        cursor.execute("INSERT INTO contacts VALUES (?, ?, ?, ?, ?, ?, ?, ?);", 
                       (contact["aimId"], contact["friendly"], contact["state"], 
                        contact["statusMsg"], contact["userType"], contact["lastseen"], 
                        contact["mute"], group["id"]))
    cursor.execute("CREATE TABLE messages (icq_number integer, type text, "
                   "direction text, timestamp_local integer, timestamp_server integer, "
                   "name text, message text);")
    gen = os.walk(os.path.join(os.path.join(profile, "archive")))
    dirpath, dirnames, _ = gen.next()
    for dirname in dirnames:
      messages = read_db2(os.path.join(os.path.join(dirpath, dirname), "_db2"))
      if "error" in messages.keys():
        print "Error while reading messages from %s: %s" % (os.path.join(os.path.join(dirpath, dirname), 
                                                            "_db2"), messages["error"])
        continue
      for message in messages["data"]:
        cursor.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?);", 
                      (dirname, message["type"], message["direction"], 
                       message["timestamp_client"], message["timestamp_server"], 
                       message["name"], message["message"]))
    
    conn.commit()
    conn.close()
    print "Successfully output profile %s to file %s" % (profile, 
                                                         os.path.join(outputdir, "%s.db" % profile[-4:]))
  print "Completed"
  
# parses the arguments
def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument("-o", "--output", 
                      help="output directory (default: current directory)")
  parser.add_argument("-i", "--input", 
                      help="input directory (default: current directory; "
                           "on Windows: %AppData%\\Roaming\\ICQ")

  args = parser.parse_args()
  
  return_args = {"input": args.input, "output": args.output}
  
  if return_args["input"] is None:
    return_args["input"] = "."
  
  if return_args["output"] is None:
    return_args["output"] = "."
  return return_args
    
args = parse_args()
write_sqlite_files(args["input"], args["output"])
