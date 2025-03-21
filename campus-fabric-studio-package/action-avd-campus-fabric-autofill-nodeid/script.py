# Copyright (c) 2023 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
# Subject to Arista Networks, Inc.'s EULA.
# FOR INTERNAL USE ONLY. NOT FOR DISTRIBUTION.

import re
import os
from typing import Dict, List, Tuple
# pylint: disable=import-error
from cloudvision.cvlib import (
    ActionFailed,
    extractStudioInfoFromArgs,
    InputUpdateException,
    InputRequestException,
    setStudioInputs,
    getStudioInputs,
    IdAllocator,
)

LOGLEVEL = 0
def log(loglevel=0, logstring=''):
   if loglevel <= LOGLEVEL:
      print(logstring)

def convert(text):
   return int(text) if text.isdigit() else text.lower()

def natural_sort(iterable, sort_key=None):
   if iterable is None:
      return []
   def alphanum_key(key):
      if sort_key is not None and isinstance(key, dict):
         return [convert(c) for c in re.split("([0-9]+)", str(key.get(sort_key, key)))]
      return [convert(c) for c in re.split("([0-9]+)", str(key))]
   return sorted(iterable, key=alphanum_key)

class Params:
   def __init__(self, stdID: str, wrkID: str, path: list):
      self.stdID = stdID
      self.wrkID = wrkID
      self.path = path
   def __copy__(self):
      return Params(self.stdID, self.wrkID, self.path)

nodeIdSettings = []

def get_value_from_tags(tags: str) -> str:
   """
   Return the value in single-tag resolver
   """
   return tags.get('query').split(':')[1] if tags.get('query') else ""

def get_inputpath_device(input_path: List, cpod_details: Dict) -> (str, str):
   """
   Return the device-type and device referenced by the input_path,
   if the input_path specifies one device
   """
   if 'spines' in input_path:
      memberType = 'spines'
      index = int(input_path[input_path.index('spines')+1])
      members = cpod_details.get('inputs').get('campusPodFacts').get('spines')
      member = members[index]
      device = get_value_from_tags(member.get('tags'))
      return memberType, device
   if 'accessPodFacts' in input_path:
      apod_index = int(input_path[input_path.index('accessPods')+1])
      memberType = input_path[input_path.index('accessPodFacts')+1]
      index = int(input_path[input_path.index(memberType)+1])
      apod = cpod_details.get('inputs').get('campusPodFacts').get('accessPods')[apod_index]
      members = apod.get('inputs').get('accessPodFacts').get(memberType)
      member = members[index]
      device = get_value_from_tags(member.get('tags'))
      return memberType, device
   if 'thirdPartyDevices' in input_path:
      index = int(input_path[input_path.index('thirdPartyDevices')+1])
      members = cpod_details.get('inputs').get('campusPodFacts').get('thirdPartyDevices')
      member = members[index]
      memberType = member.get('role')
      if 'spine' in memberType:
         memberType = 'spines'
      device = member.get('identifier')
      return memberType, device
   return None, None

def get_spines_from_cpod(cpod_details: Dict,
   id_alloc: IdAllocator) -> Dict:
   """
   Return a dictionary of spine nodeIds already allocated in campus pod
   """
   spines_nodeIds = {}
   cpodSpines = cpod_details.get('inputs').get('campusPodFacts').get('spines')
   for spine in cpodSpines:
      if not (inputs := spine.get('inputs')) or \
         not (tags := spine.get('tags')) or \
         not (spine_dev := get_value_from_tags(tags)):
         continue
      spine_nodeId = inputs.get('spinesInfo').get('nodeId')
      spines_nodeIds[spine_dev] = spine_nodeId
      if spine_nodeId:
         try:
            id_alloc.allocate(spine_nodeId, spine_dev)
         except (ValueError, AssertionError) as error:
            raise ActionFailed((f"Spine {spine_dev} Node Id Error: {error}")) from error
   thirdPartyDevs = cpod_details.get('inputs').get('campusPodFacts').get('thirdPartyDevices', [])
   for dev in thirdPartyDevs:
      if not (role := dev.get('role')) or not dev.get(
         'identifier') or 'spine' not in role :
         continue
      spine_nodeId = dev.get('nodeId')
      spine_dev = dev.get('identifier')
      spines_nodeIds[spine_dev] = spine_nodeId
      if spine_nodeId:
         try:
            id_alloc.allocate(spine_nodeId, spine_dev)
         except (ValueError, AssertionError) as error:
            raise ActionFailed((f"Spine {spine_dev} Node Id Error: {error}")) from error
   return spines_nodeIds

def generate_spine_nodeIds(spines_nodeIds: Dict, id_alloc: IdAllocator,
   device: str=None) -> Dict:
   """
   Return a dictionary of spine nodeIds fully allocated in campus pod
       - { <device>: <nodeId>, ... }
   """
   for spine, nodeId in spines_nodeIds.items():
      if not nodeId:
         if device and spine != device:
            continue
         try:
            spines_nodeIds[spine] = id_alloc.allocate(name=spine)
         except (ValueError, AssertionError) as error:
            raise ActionFailed((f"Spine {spine} Node Id Error: {error}")) from error
   return spines_nodeIds

def get_members_from_apod(apod_facts: Dict, apod_name: Dict, apod_members: Dict,
   id_alloc: IdAllocator, memberType: str) -> Dict:
   """
   Return a two level dictionary of access pod nodeIds already allocated,
   in a campus pod, for a access pod memberType, ie. leafs or memberLeafs
       - { <access_pod_name>: { <device>: <nodeId>, ... }, ... }
   """
   for apod_member in apod_facts.get(memberType):
      if not (inputs := apod_member.get('inputs')) or \
         not (tags := apod_member.get('tags')) or \
         not (member_device := get_value_from_tags(tags)):
         continue
      if memberInfo := inputs.get(memberType + 'Info'):
         member_nodeId = memberInfo.get('nodeId')
      else:
         member_nodeId = None
      apod_members.setdefault(apod_name, {})[member_device] = member_nodeId
      if member_nodeId:
         try:
            id_alloc.allocate(member_nodeId, member_device)
         except (ValueError, AssertionError) as error:
            raise ActionFailed((f"Leaf {member_device} Node Id Error: {error}")) from error
   return apod_members

def generate_apod_nodeIds(apod_members: Dict, id_alloc: IdAllocator,
   device: str=None) -> Dict:
   """
   Return a dictionary of access pod nodeIds fully allocated in campus pod,
   for a access pod memberType, ie. leafs or memberLeafs.
       - { <device>: <nodeId>, ... }
   For unfilled nodeIds, generate based on access pod sorted alphanumberically
   """
   member_nodeIds = {}
   apod_members = {key: dict(natural_sort(
                    apod_members[key].items())) for key in natural_sort(
                       apod_members)}
   for _, members in apod_members.items():
      for member, nodeId in members.items():
         if not nodeId:
            if device and member != device:
               continue
            try:
               members[member] = id_alloc.allocate(name=member)
            except (ValueError, AssertionError) as error:
               raise ActionFailed((f"Leaf {member} Node Id Error: {error}")) from error
         member_nodeIds[member] = members[member]
   return member_nodeIds

def get_nodeIds(device: str, campusType: str, cpod_details: Dict) -> Dict:
   """
   Return a dictionary of nodeIds allocated in campus pod.
   If device is specified, generate nodeId only for that device
   """
   member_nodeIds = {}
   if not (cpod_inputs := cpod_details.get('inputs')) or \
      not (cpod_tags := cpod_details.get('tags')) or \
      not get_value_from_tags(cpod_tags):
      return member_nodeIds
   # for an L2 campus allocate both leafs and mleafs from the same allocator
   sid_alloc = IdAllocator()
   if 'l2' in campusType.lower():
      lid_alloc = IdAllocator()
      mid_alloc = lid_alloc
   else:
      lid_alloc = IdAllocator()
      mid_alloc = IdAllocator()

   # spines
   spine_nodeIds = get_spines_from_cpod(cpod_details, sid_alloc)
   spine_nodeIds = generate_spine_nodeIds(spine_nodeIds, sid_alloc, device)

   # leafs and memberLeafs
   #   - get all members of all apods
   #   - for an L2 campus get both leafs and mleafs
   leaf_members = {}
   mleaf_members = {}
   apods = cpod_inputs.get('campusPodFacts').get('accessPods')
   for apod in apods:
      if not (apod_details := apod.get('inputs')) or \
         not (apod_facts := apod_details.get('accessPodFacts')) or \
         not (apod_tags := apod.get('tags')) or \
         not (apod_name := get_value_from_tags(apod_tags)):
         continue
      leaf_members = get_members_from_apod(apod_facts, apod_name, leaf_members,
                                         lid_alloc, 'leafs')
      mleaf_members = get_members_from_apod(apod_facts, apod_name, mleaf_members,
                                         mid_alloc, 'memberLeafs')
   leaf_nodeIds = generate_apod_nodeIds(leaf_members, lid_alloc, device)
   mleaf_nodeIds = generate_apod_nodeIds(mleaf_members, mid_alloc, device)
   member_nodeIds = spine_nodeIds | leaf_nodeIds | mleaf_nodeIds
   return member_nodeIds

def set_nodeId(params: Params, nodeId: int):
   """
   Set the nodeId for the input path device in the inputs
   """
   nodeIdSettings.append((params.path, nodeId))

def sendNodeIdSettings(stdID: str, wrkID: str, inputs: List[Tuple]):
   """
   Send the nodeId settings to the Inputs Service
   """
   try:
      # pylint: disable=undefined-variable
      setStudioInputs(ctx.getApiClient, stdID, wrkID, inputs)
   except InputUpdateException as error:
      raise ActionFailed(("Failed to update input associated with nodeIds. "
                          "Please assign them manually.")) from error

def set_spineIds(params: Params, cpod_details: Dict, relevant_nodeIds: Dict):
   """
   Set the nodeId for the spines in a cpod
   """
   if not (cpod_inputs := cpod_details.get('inputs')) or \
      not (cpod_tags := cpod_details.get('tags')) or \
      not get_value_from_tags(cpod_tags):
      return
   base_path = params.path[:-2]
   local_params = params.__copy__()
   # process arista spines
   cpodSpines = cpod_inputs.get('campusPodFacts').get('spines')
   for idx, spine in enumerate(cpodSpines):
      if not (inputs := spine.get('inputs')) or \
         not (tags := spine.get('tags')) or \
         not (dev := get_value_from_tags(tags)):
         continue
      nodeId = inputs.get('spinesInfo').get('nodeId')
      if relevant_nodeIds and nodeId:
         continue
      if not relevant_nodeIds and not nodeId:
         continue
      nodeId = relevant_nodeIds.get(dev)
      local_params.path = base_path + ['spines', str(idx), 'inputs',
                                       'spinesInfo', 'nodeId']
      set_nodeId(local_params, nodeId)
   # process third party spines from separate section of inputs
   thirdPartyDevs = cpod_details.get('inputs').get('campusPodFacts').get('thirdPartyDevices', [])
   for idx, thirdDev in enumerate(thirdPartyDevs):
      if not (role := thirdDev.get('role')) or not thirdDev.get(
         'identifier') or 'spine' not in role :
         continue
      nodeId = thirdDev.get('nodeId')
      if relevant_nodeIds and nodeId:
         continue
      if not relevant_nodeIds and not nodeId:
         continue
      dev = thirdDev.get('identifier')
      nodeId = relevant_nodeIds.get(dev)
      local_params.path = base_path + ['thirdPartyDevices', str(idx), 'nodeId']
      set_nodeId(local_params, nodeId)

def set_members_in_apod(params: Params, relevant_nodeIds: Dict,
                        apod_facts: Dict, apodIdx: int, memberType: str):
   """
   Set the nodeId for the member type in the access pod
   """
   base_path = params.path[:-2]
   local_params = params.__copy__()
   for idx, apod_member in enumerate(apod_facts.get(memberType)):
      if not (inputs := apod_member.get('inputs')) or \
         not (tags := apod_member.get('tags')) or \
         not (dev := get_value_from_tags(tags)):
         continue
      if memberInfo := inputs.get(memberType + 'Info'):
         nodeId = memberInfo.get('nodeId')
      else:
         nodeId = None
      if relevant_nodeIds and nodeId:
         continue
      if not relevant_nodeIds and not nodeId:
         continue
      nodeId = relevant_nodeIds.get(dev)
      local_params.path = base_path + ['accessPods', str(apodIdx), 'inputs',
                                       'accessPodFacts', memberType, str(idx),
                                       'inputs', memberType + 'Info', 'nodeId']
      set_nodeId(local_params, nodeId)

def set_apodIds(params: Params, cpod_details: Dict, relevant_nodeIds: Dict):
   """
   Set the nodeId for the leafs and mleafs in a cpod
   """
   if not (cpod_inputs := cpod_details.get('inputs')) or \
      not (cpod_tags := cpod_details.get('tags')) or \
      not get_value_from_tags(cpod_tags):
      return
   apods = cpod_inputs.get('campusPodFacts').get('accessPods')
   for idx, apod in enumerate(apods):
      if not (apod_details := apod.get('inputs')) or \
         not (apod_facts := apod_details.get('accessPodFacts')) or \
         not (apod_tags := apod.get('tags')) or \
         not get_value_from_tags(apod_tags):
         continue
      set_members_in_apod(params, relevant_nodeIds, apod_facts, idx, 'leafs')
      set_members_in_apod(params, relevant_nodeIds, apod_facts, idx, 'memberLeafs')

def main():
   if os.environ.get("TEST_ONLY"):
      return
   # pylint: disable=undefined-variable
   stdID, wrkID, input_path = extractStudioInfoFromArgs(ctx.action.args)
   try:
      inputs = getStudioInputs(ctx.getApiClient, stdID, wrkID)
   except InputRequestException as error:
      raise ActionFailed((f"Failed to get input associated with {stdID}.")) from error

   # only care about the campus pod of input path device
   campus_index = int(input_path[input_path.index('campus')+1])
   cpod_index = int(input_path[input_path.index('campusPod')+1])
   campus_details = inputs.get('campus')[campus_index]
   cpod_details = campus_details.get('inputs').get('campusDetails').get(
                         'campusPod')[cpod_index]
   if not (cpod_inputs := cpod_details.get('inputs')) or \
      not (cpod_tags := cpod_details.get('tags')) or \
      not get_value_from_tags(cpod_tags):
      return
   campusType = cpod_inputs.get('campusPodFacts').get('design').get('campusType')
   device_type, device = get_inputpath_device(input_path, cpod_details)
   if device_type and device_type not in ['leafs', 'memberLeafs', 'spines']:
      raise ActionFailed((f"Invalid input device type {device_type}."))

   # get nodeIds related to input path device, generate if nodeId is missing
   # use campusType not set as a signal to clear nodeIds
   relevant_nodeIds = {}
   if campusType:
      relevant_nodeIds = get_nodeIds(device, campusType, cpod_details)
   else:
      log(0, "Campus Type field is unset, clearing Node Id field")

   # set or clear nodeIds
   params = Params(stdID, wrkID, input_path)
   if device:
      nodeId = relevant_nodeIds.get(device)
      set_nodeId(params, nodeId)
   else:
      set_spineIds(params, cpod_details, relevant_nodeIds)
      set_apodIds(params, cpod_details, relevant_nodeIds)

   if nodeIdSettings:
      sendNodeIdSettings(stdID, wrkID, nodeIdSettings)

if __name__ == "__main__":
   main()
