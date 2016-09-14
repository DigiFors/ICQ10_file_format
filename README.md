# ICQ 10 file format

In digital investigations, chat logs are often important pieces of evidence. Most instant messengers use well-known file formats such as SQLite databases or even plain text XML and JSON files. ICQ 10 uses a proprietary file format which, as far as we know, is not documented anywhere.

This document is based on files generated by ICQ 10.0.12114 on Windows and ICQ 3.0.5212 on Mac OS X.

# Finding the right files

On Windows, the ICQ directory can be found under %AppData%\Roaming\ICQ. The ICQ directory contains profile directories named "0001" for the first profile, "0002" for the second profile, and so on. A profile directory contains several subdirectories:
- `\archive` has subdirectories which are named after ICQ numbers. They include the chat history with the person in question.
- `\contacts` contains a file called cache.cl, which is a plain JSON file containing the contacts and contact groups.
- `\content.cache` has a file for exchanged files. Those files include either the file URL on ICQ's servers or, in the case of images, the file itself. So far, I've not been able to find out how the file names are determined.
- `\dialogs` contains a file called cache2 which is again a JSON file with chat partners.
- `\info` has a file called cache which stores some basic info about the user the profile belongs to.
- `\key` contains files called fetch and value.au. I have not yet been able to determine what they're used for.
- `\stickers` has ICQ images ("stickers").

# Binary files

In the following, we will concentrate on two files: the info cache, which contains information about the user the profile belongs to, and the `_db2` files which can be found in the archive subdirectories, which contain chat histories.

# Basics

All files contain blocks. A block may be the entire user info or a message in a `_db2` file.
Blocks start and end with their length (excluding the length values), as four-byte little-endian integer, written twice.

For instance, a block might look like this:

`10 00 00 00 10 00 00 00` <- length, written twice

`00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f` <- block data

`10 00 00 00 10 00 00 00` <- length, written twice

All values are little-endian.

# The info cache

Everything in this file is contained in a block.

The block contains several pieces. All pieces start with a four-byte integer, followed by the length of the data (again as a four-byte integer), followed by the data.

Start integer | Data
------------- | ----
1 | ICQ number written as ASCII string
2 | The same?
3 | User name
4 | Status
5 | Type of account (ICQ/AIM)
6 | Phone number (with country prefix, without +)
7 | Unknown

# _db2 files

Those files contain several blocks. Every block represents a message or an event (contact added, call started, call ended).

## Basic message

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | always 0x01
0x04   | 4      | always 0x08
0x08   | 4      | unknown
0x0c   | 4      | UNIX timestamp of the message as reported by the server
0x10   | 4      | always 0x0d
0x14   | 4      | always 0x08
0x18   | 4      | if first message: 0xffffffff, otherwise: unknown
0x1c   | 4      | if first message: 0xffffffff, otherwise: server timestamp of the last message
0x20   | 4      | always 0x02
0x24   | 4      | always 0x04
0x28   | 4      | 0x00 if incoming, 0x04 if outgoing
0x2c   | 4      | always 0x03
0x30   | 4      | always 0x08
0x34   | 4      | UNIX timestamp of the message as reported by the client
0x38   | 4      | always 0x00
0x3c   | 4      | always 0x04

Incoming message or file only:

Offset | Length | Information
------ | ------ | -----------
0x40   | 4      | length of the GUID = len_guid
0x44   | len_guid | GUID. 8-4-4-4, allowed characters are 0-9 and a-f.
0x44+len_guid | 4 | 0x0e if there is a name, or 0x15 otherwise
0x44+len_guid+0x04 | 4 | always 0x00 (probably the second GUID length = 0, since there is no second GUID)
0x44+len_guid+0x08 | 4 | 0x15 if there is a name, or 0x05 otherwise

Outgoing message or file only:

Offset | Length | Information
------ | ------ | -----------
0x40   | 4      | always 0x00
0x44   | 4      | always 0x0e
0x48   | 4      | length of the GUID = len_guid
0x4c   | len_guid | GUID. 8-4-4-4-ID, allowed characters are 0-9 and a-f. ID is a counter that starts at 1.
0x4c+len_guid | 4 | 0x0e if there is a name, or 0x15 otherwise
0x44+len_guid+0x04 | 4 | length of second GUID (for outgoing files, otherwise 0) = len_guid_2
0x44+len_guid+0x08 | len_guid_2 | second GUID
0x4c+len_guid+0x08+len_guid_2 | 4 | 0x15 if there is a name, or 0x05 otherwise

Other records:

Offset | Length | Information
------ | ------ | -----------
0x48   | 4      | always 0x00 (probably the GUID length = 0, since there is no GUID)
0x4c   | 4      | 0x0e if there is a name, or 0x15 otherwise
0x50   | 4      | 0x00 (probably the second GUID length = 0, since there is no second GUID)
0x54   | 4      | 0x15 if there is a name, or 0x05 otherwise

If there is a name (continued with resetted offset):

Offset | Length | Information
------ | ------ | -----------
0x00 | 4 | length of name = len_name
0x04 | len_name | name
0x04+len_name | 4 | always 0x05

Continued with resetted offset:

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | length of message = len_message
0x04   | len_message | message

## Files

Files have an URL starting with https://files.icq.net/get/ as the message. If the file is outgoing, it has a second GUID as described above, and the message is followed by the four-byte integers 0x10, 0x43, 0x12 and then again message length and message.

## Added/removed contacts

For this, the message is always "added you to contacts" or similar in the language ICQ is configured with - even if the user himself added the remote peer as contact or the contact was removed! However, the direction indicators as above work. Whether the action was adding or removing the contact can not be determined from the record alone. After the message, there are some special fields:

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | always 0x16
0x04   | 4      | always 0x31
0x08   | 4      | always 0x17
0x0c   | 4      | always 0x04
0x10   | 4      | always 0x02
0x14   | 4      | always 0x2b
0x18   | 4      | length of ICQ number = len_icq
0x1c   | len_icq | ICQ number as ASCII string
0x1c+len_icq | 4 | unknown
0x1c+len_icq+0x04 | 4 | length of name, if a name is set, or of ICQ number, if no name is set = len_noi
0x1c+len_icq+0x08 | len_noi | name, if a name is set, or ICQ number, if no name is set

## Calls

Calls always have two messages: a message for the start of the call and a message for the end of the call. If there's no answer, only the end message will be in the file.

The start call message has an empty message body with some special fields after the message:

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | always 0x09
0x04   | 4      | unknown
0x08   | 4      | always 0x1b
0x0c   | 4      | always 0x04
0x10   | 4      | always 0x04
0x14   | 4      | always 0x1d

Fields from 0x18 are as in the add contact message. If it was an incoming call, there are some extra fields after the field that contains either the name or the ICQ number:

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | always 0x1f
0x04   | 4      | always 0x04
0x08   | 4      | always 0x01

The end call message is very similar, here are the fields after the message:

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | always 0x09
0x04   | 4      | unknown
0x08   | 4      | always 0x1b
0x0c   | 4      | always 0x04
0x10   | 4      | always 0x03
0x14   | 4      | always 0x1d

If the call was completed (i.e. not no answer), there are some extra fields after the field that contains either the name or the ICQ number:

Offset | Length | Information
------ | ------ | -----------
0x00   | 4      | always 0x1e
0x04   | 4      | always 0x04
0x08   | 4      | always 0x12
0x0c   | 4      | unknown
0x10   | 4      | always 0x04
0x14   | 4      | unknown

We hope this document is useful. Contact us at info@digifors.de if you have any comments, questions or corrections.
