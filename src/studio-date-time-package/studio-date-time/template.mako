<%
from cloudvision import cvlib

device = ctx.getDevice()
%>
%  if timezoneResolver:
  <% tzGroup = timezoneResolver.resolve().get("timezoneGroup") %>
%    if tzGroup:
  <%
    tz = tzGroup.get("timezone")
    if not tz or tz == "Other":
      tz = tzGroup.get("otherTimezone")
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
%    for ntpserver in ntpServerResolver.resolve().get("ntpServers", []):
<%
# Determine VRF to use - source interface VRF takes precedence
vrfToUse = ntpSrcIntfVrf if ntpSrcIntfVrf else ntpserver.get('vrf')

# Determine source interface to use
sourceIntfToUse = None
if ntpSrcIntf:
    if ntpSrcIntf == "Use OOB Management Interface":
        sourceIntfToUse = device.getPrimaryManagementIntf(ctx)
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
