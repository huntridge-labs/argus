WEBINIT ; InterSystems ObjectScript / Cache routine, not standard VistA-M
 ; The VistA-M grammar mangles class syntax / dot-methods, so the
 ; VistA-M-specific structural rules (M201, M203) must skip this file
 ; rather than emit wholesale false positives.
 n % s %=##class(Config.Namespaces).Get(NMSP,.PROP)
 i '% w $SYSTEM.Status.GetErrorText(%)
 s response=httprequest.HttpResponse.Data
 d ..ProcessRequest(config.GetGlobalMapping)
 q
