<%
from arista.tag.v2.services import (
    TagAssignmentServiceStub,
    TagAssignmentStreamRequest
)
from arista.tag.v2.tag_pb2 import (
    TagAssignment,
    ELEMENT_TYPE_DEVICE,
    CREATOR_TYPE_SYSTEM
)
from cloudvision import cvlib

device = ctx.getDevice()
MAINLINE_ID = ""

@ctx.benchmark
def getPrimaryManagementIntf():
    mgmtIntfs = []
    for intf in device.getInterfaces():
        if intf.name.startswith("Management"):
            mgmtIntfs.append(intf.name)
    if not mgmtIntfs:
        return ""
    mgmtIntfs.sort()
    tagClient = ctx.getApiClient(TagAssignmentServiceStub)
    tagRequest = TagAssignmentStreamRequest()
    tagFilter = TagAssignment()
    tagFilter.tag_creator_type = CREATOR_TYPE_SYSTEM
    tagFilter.key.element_type = ELEMENT_TYPE_DEVICE
    tagFilter.key.workspace_id.value = MAINLINE_ID
    tagFilter.key.label.value = "systype"
    tagFilter.key.device_id.value = ctx.getDevice().id
    tagRequest.partial_eq_filter.append(tagFilter)
    systemType = ""
    primaryMgmtIntf = ""
    for resp in tagClient.GetAll(tagRequest):
        systemType = resp.value.key.value.value
    if systemType.lower() == "fixed":
        primaryMgmtIntf = "Management1"
    elif systemType.lower() == "modular":
        primaryMgmtIntf = "Management0"
    else:
        return None
    # There are cases where Mgmt0 and Mgmt1 are not present and a different primary interface is needed.
    # For example, devices with AWE sku have systype tag as fixed but don't have management1 on the
    # device but Management1/1 interface instead.
    # Checking this only for fixed systems as Management0 is not a physical interface
    # and is not returned by device object.
    if primaryMgmtIntf == "Management1" and primaryMgmtIntf not in mgmtIntfs:
        primaryMgmtIntf = mgmtIntfs[0]
    return primaryMgmtIntf
%>
%  if timezoneResolver:
  <% tzGroup = timezoneResolver.resolve()["timezoneGroup"] %>
%    if tzGroup:
  <%
    if tzGroup["timezone"] and tzGroup["timezone"] != "Other":
      tz = tzGroup["timezone"]
    else:
      tz = tzGroup["otherTimezone"]
  %>
%      if tz:
clock timezone ${tz}
%      endif
%    endif
%  endif

<%
inputErrors = []
# Get NTP source interface settings
ntpSrcIntfSettings = None
ntpSrcIntfVrf = None
ntpSrcIntf = None
ntpSrcIP = None
if ntpSourceInterfaceResolver:
    ntpSrcIntfSettings = ntpSourceInterfaceResolver.resolve().get("ntpSourceInterfaceGroup")
    if ntpSrcIntfSettings:
        ntpSrcIntfVrf = ntpSrcIntfSettings.get("managementVrf")
        ntpSrcIntf = ntpSrcIntfSettings.get("sourceInterface")
        ntpSrcIP = ntpSrcIntfSettings.get("sourceAddress")
%>

%  if ntpServerResolver:
%    for ntpserver in ntpServerResolver.resolve()["ntpServers"]:
<%
# Determine VRF to use - source interface VRF takes precedence
vrfToUse = ntpSrcIntfVrf if ntpSrcIntfVrf else ntpserver.get('vrf')

# Determine source interface to use
sourceIntfToUse = None
if ntpSrcIntf:
    if ntpSrcIntf == "Use OOB Management Interface":
        sourceIntfToUse = getPrimaryManagementIntf()
        if not sourceIntfToUse:
            message = f'No management interface present for the device {device.hostName}.'
            inputPath = ["ntpSourceInterfaceResolver"]
            fieldId = "sourceInterface"
            inputErrors.append(cvlib.InputError(message=message, inputPath=inputPath, fieldId=fieldId))
    else:
        sourceIntfToUse = ntpSrcIntf
if inputErrors:
    raise cvlib.InputErrorException(inputErrors=inputErrors)
%>
ntp server\
%      if vrfToUse:
 vrf ${vrfToUse}\
%      endif
 ${ ntpserver['ntpServer'] }\
%      if sourceIntfToUse:
 source ${sourceIntfToUse}\
%      endif
%      if ntpSrcIP:
 source-address ${ntpSrcIP}\
%      endif
%      if ntpserver['preferred']:
 prefer\
%      endif
%      if ntpserver['iburst']:
 iburst\
%      endif

%    endfor
%  endif
