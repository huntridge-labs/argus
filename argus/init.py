"""argus init — project detection and config generation.

Detects project languages, frameworks, and infrastructure to generate
a tailored argus.yml with the right scanners enabled.
"""

import sys
from pathlib import Path

# Banner displayed on init — generated from the Argus brandmark
# using ascii_magic. Static string, no runtime dependency.
_BANNER = """\
                                \033[38;2;160;255;98mU\033[38;2;165;206;93mY\033[38;2;160;192;87mG\033[38;2;158;186;88mP\033[38;2;160;188;89mP\033[38;2;163;191;87mG\033[38;2;162;192;89mG\033[38;2;162;191;88mGG\033[38;2;164;191;89mG\033[38;2;165;195;90mZ\033[38;2;162;198;90mZ\033[38;2;160;191;89mG\033[38;2;163;198;89mZ\033[38;2;172;196;85mZ\033[38;2;98;255;98mb\033[0m                                \033[0m
                          \033[38;2;255;255;55m@\033[38;2;154;192;84mP\033[38;2;151;181;82mg\033[38;2;153;184;85mX\033[38;2;152;185;85mX\033[38;2;153;185;85mX\033[38;2;154;185;85mX\033[38;2;156;186;86mX\033[38;2;157;188;86mP\033[38;2;159;189;87mP\033[38;2;163;193;89mG\033[38;2;167;199;91mb\033[38;2;169;202;91mb\033[38;2;172;205;92mYYY\033[38;2;172;203;92mY\033[38;2;168;200;91mb\033[38;2;163;193;89mG\033[38;2;162;191;88mG\033[38;2;163;193;89mG\033[38;2;162;192;89mG\033[38;2;162;192;88mG\033[38;2;163;193;89mG\033[38;2;163;192;89mG\033[38;2;167;199;91mb\033[38;2;165;206;93mY\033[0m                           \033[0m
                       \033[38;2;145;177;81mE\033[38;2;144;177;81m4\033[38;2;145;180;81mE\033[38;2;145;178;81mE\033[38;2;145;178;82mE\033[38;2;150;184;83mg\033[38;2;157;192;85mP\033[38;2;158;193;87mG\033[38;2;159;193;87mG\033[38;2;162;196;87mG\033[38;2;164;199;89mZ\033[38;2;167;200;90mb\033[38;2;168;202;90mb\033[38;2;167;199;90mb\033[38;2;163;193;89mG\033[38;2;162;192;89mGG\033[38;2;160;192;89mG\033[38;2;162;191;89mG\033[38;2;162;192;88mG\033[38;2;160;192;89mG\033[38;2;162;191;88mG\033[38;2;160;192;88mG\033[38;2;162;192;88mGG\033[38;2;162;192;89mG\033[38;2;160;191;88mG\033[38;2;167;199;90mb\033[38;2;164;196;89mZ\033[38;2;162;193;89mG\033[38;2;163;195;89mGG\033[38;2;163;192;89mG\033[38;2;160;193;89mG\033[0m                       \033[0m
                    \033[38;2;141;170;79md\033[38;2;139;173;79md\033[38;2;139;174;79md\033[38;2;140;173;79md\033[38;2;146;182;81mE\033[38;2;150;185;82mX\033[38;2;147;182;82mg\033[38;2;146;181;82mE\033[38;2;150;184;83mg\033[38;2;154;189;85mP\033[38;2;157;192;86mP\033[38;2;151;182;83mg\033[38;2;152;185;85mX\033[38;2;154;186;85mX\033[38;2;157;189;86mP\033[38;2;158;189;85mP\033[38;2;159;192;88mG\033[38;2;158;192;89mG\033[38;2;158;192;87mP\033[38;2;154;192;84mP\033[38;2;160;203;87mb\033[38;2;153;182;89mX\033[38;2;150;196;85mP\033[38;2;177;177;81mXX\033[38;2;188;188;98mb\033[38;2;169;208;88mY\033[38;2;150;196;85mP\033[38;2;164;196;85mG\033[38;2;168;202;89mb\033[38;2;164;193;90mG\033[38;2;163;193;87mG\033[38;2;165;198;89mZ\033[38;2;167;196;90mZ\033[38;2;165;196;89mZ\033[38;2;165;195;89mZZ\033[38;2;168;199;89mb\033[38;2;162;191;87mG\033[0m                     \033[0m
                 \033[38;2;128;168;76mh\033[38;2;133;169;76mV\033[38;2;133;169;77mV\033[38;2;134;170;77mV\033[38;2;142;180;80mE\033[38;2;142;178;80m4\033[38;2;140;174;79m4\033[38;2;140;173;79md\033[38;2;143;178;81m4\033[38;2;150;186;83mX\033[38;2;146;181;82mE\033[38;2;145;178;82mE\033[38;2;149;180;82mE\033[38;2;150;182;83mg\033[38;2;149;185;84mX\033[38;2;160;203;87mb\033[0m                   \033[38;2;107;150;71mp\033[38;2;109;154;71m6\033[38;2;101;146;68m5\033[38;2;98;125;64mC\033[38;2;203;203;98mA\033[38;2;186;211;95mO\033[38;2;191;211;103mA\033[0m                     \033[0m
               \033[38;2;126;165;74mg\033[38;2;131;168;76mh\033[38;2;130;165;76mh\033[38;2;136;173;77md\033[38;2;136;173;78md\033[38;2;133;169;77mV\033[38;2;133;168;77mh\033[38;2;135;170;78mV\033[38;2;142;178;80m4\033[38;2;144;181;81mE\033[38;2;141;176;79m4\033[38;2;143;177;80m4\033[38;2;142;177;82m4\033[38;2;142;181;77mE\033[0m          \033[38;2;162;193;89mG\033[38;2;163;192;89mG\033[0m          \033[38;2;98;98;98mn\033[38;2;115;158;73mm\033[38;2;117;159;73mq\033[38;2;115;158;72mm\033[38;2;114;158;73mm\033[38;2;112;156;72mm\033[38;2;111;153;71m66\033[38;2;114;160;71mq\033[38;2;111;160;70mm\033[0m                   \033[0m
             \033[38;2;130;167;75mh\033[38;2;131;168;76mh\033[38;2;131;167;75mh\033[38;2;136;174;77md\033[38;2;131;168;76mh\033[38;2;129;164;75mg\033[38;2;130;165;76mh\033[38;2;131;167;76mh\033[38;2;138;174;78md\033[38;2;138;173;78md\033[38;2;139;172;78md\033[38;2;136;170;78mV\033[38;2;141;173;84m4\033[0m          \033[38;2;255;255;55m@\033[38;2;167;192;87mG\033[38;2;164;195;89mG\033[38;2;167;198;90mZ\033[38;2;165;196;90mZZ\033[38;2;163;195;88mG\033[38;2;255;255;98mW\033[0m          \033[38;2;117;153;71mm\033[38;2;115;156;72mm\033[38;2;114;157;72mm\033[38;2;118;164;74mS\033[38;2;120;170;75mg\033[38;2;111;154;72m6\033[38;2;110;153;71m6\033[38;2;110;154;71m6\033[38;2;110;153;71m6\033[38;2;109;157;71m6\033[38;2;109;152;72mp\033[0m               \033[0m
           \033[38;2;128;163;76mg\033[38;2;130;167;76mh\033[38;2;131;167;76mh\033[38;2;135;174;77md\033[38;2;130;167;76mh\033[38;2;129;164;75mggg\033[38;2;132;169;76mh\033[38;2;135;172;77mV\033[38;2;133;168;77mh\033[38;2;134;169;78mV\033[38;2;136;136;72mp\033[0m       \033[38;2;167;192;91mG\033[38;2;172;205;89mY\033[38;2;165;192;89mG\033[38;2;163;192;88mG\033[38;2;163;193;89mG\033[38;2;162;193;89mGG\033[38;2;170;203;91mY\033[38;2;163;193;89mGG\033[38;2;170;203;91mY\033[38;2;163;193;89mG\033[38;2;164;193;89mGG\033[38;2;164;195;89mG\033[38;2;162;191;90mG\033[38;2;167;202;91mb\033[38;2;160;203;87mb\033[0m        \033[38;2;112;154;72m6\033[38;2;113;157;72mm\033[38;2;112;158;72mm\033[38;2;115;163;73mq\033[38;2;113;160;73mq\033[38;2;113;162;73mq\033[38;2;110;156;72m6\033[38;2;108;152;71mp\033[38;2;107;154;71mp\033[38;2;105;153;71mp\033[38;2;106;150;70mF\033[0m            \033[0m
         \033[38;2;112;150;67mp\033[38;2;129;164;75mg\033[38;2;131;167;76mh\033[38;2;136;174;77md\033[38;2;130;167;76mh\033[38;2;129;164;75mgggg\033[38;2;133;169;76mV\033[38;2;131;167;76mh\033[38;2;130;167;76mh\033[38;2;160;160;64mh\033[0m         \033[38;2;163;192;89mG\033[38;2;168;200;91mb\033[38;2;160;191;88mG\033[38;2;169;200;91mb\033[38;2;172;205;92mY\033[38;2;168;200;91mb\033[38;2;163;193;89mG\033[38;2;162;192;89mGGGG\033[38;2;163;193;89mG\033[38;2;168;200;91mb\033[38;2;172;205;92mY\033[38;2;169;202;91mb\033[38;2;163;193;89mG\033[38;2;169;202;91mb\033[38;2;162;192;89mG\033[0m          \033[38;2;110;156;72m6\033[38;2;112;157;72mm\033[38;2;112;158;72mm\033[38;2;109;153;71mp\033[38;2;108;152;71mp\033[38;2;109;156;72m6\033[38;2;111;159;72mmm\033[38;2;106;152;71mp\033[38;2;105;152;71mp\033[38;2;105;154;71mp\033[38;2;98;145;68m2\033[0m         \033[0m
        \033[38;2;125;160;73mS\033[38;2;130;165;76mh\033[38;2;136;176;77md\033[38;2;131;168;76mh\033[38;2;129;164;75mggggg\033[38;2;133;169;76mV\033[38;2;130;165;76mh\033[38;2;128;168;76mh\033[0m           \033[38;2;169;188;88mG\033[38;2;162;191;88mG\033[38;2;172;205;92mY\033[38;2;162;192;89mGGGGGGGGGGGG\033[38;2;168;200;91mb\033[38;2;163;193;89mG\033[38;2;157;195;88mG\033[0m           \033[38;2;111;142;70m5\033[38;2;111;153;72m6\033[38;2;111;158;72mm\033[38;2;109;153;71mp\033[38;2;108;152;71mp\033[38;2;107;152;71mp\033[38;2;106;151;71mp\033[38;2;106;153;71mp\033[38;2;108;158;72m66\033[38;2;104;151;71mF\033[38;2;105;151;69mF\033[0m        \033[0m
        \033[38;2;127;165;76mg\033[38;2;129;165;76mh\033[38;2;130;167;76mh\033[38;2;136;174;77md\033[38;2;132;169;76mh\033[38;2;130;165;75mh\033[38;2;129;164;75mggg\033[38;2;133;169;76mV\033[38;2;130;165;75mh\033[38;2;122;154;74mq\033[0m            \033[38;2;160;188;87mP\033[38;2;164;195;89mG\033[38;2;172;205;92mY\033[38;2;162;192;89mGGGGGGGGGG\033[38;2;168;200;91mb\033[38;2;165;198;90mZ\033[38;2;160;191;89mG\033[0m            \033[38;2;111;154;70m6\033[38;2;111;156;72mm\033[38;2;111;157;72mm\033[38;2;109;153;71mp\033[38;2;108;152;71mp\033[38;2;107;152;71mp\033[38;2;106;152;71mp\033[38;2;105;151;71mp\033[38;2;108;156;71m6\033[38;2;108;157;71m6\033[38;2;104;151;71mF\033[38;2;101;146;68m5\033[0m        \033[0m
          \033[38;2;132;168;76mh\033[38;2;130;165;76mhhh\033[38;2;136;174;77md\033[38;2;133;170;76mV\033[38;2;131;167;76mh\033[38;2;129;164;75mg\033[38;2;133;169;76mV\033[38;2;131;167;76mh\033[38;2;130;167;76mh\033[38;2;136;177;72md\033[0m           \033[38;2;154;189;86mP\033[38;2;164;195;89mG\033[38;2;169;202;91mb\033[38;2;168;200;91mb\033[38;2;162;192;89mGGGGGG\033[38;2;165;196;90mZ\033[38;2;173;206;92mY\033[38;2;165;196;89mZ\033[38;2;162;191;89mG\033[0m           \033[38;2;98;98;98mn\033[38;2;114;158;73mm\033[38;2;114;158;72mm\033[38;2;113;158;73mm\033[38;2;111;153;72m6\033[38;2;110;153;71m6\033[38;2;109;153;71mp\033[38;2;108;152;71mp\033[38;2;109;156;71m6\033[38;2;111;160;72mm\033[38;2;107;153;71mp\033[38;2;105;152;71mp\033[0m          \033[0m
            \033[38;2;136;169;72mV\033[38;2;131;165;76mh\033[38;2;131;167;75mh\033[38;2;130;165;75mh\033[38;2;129;164;75mg\033[38;2;134;172;77mV\033[38;2;135;174;77md\033[38;2;136;174;77md\033[38;2;138;177;78m4\033[38;2;130;167;76mh\033[38;2;131;167;75mh\033[38;2;125;160;77mS\033[0m          \033[38;2;98;160;64mF\033[38;2;162;195;88mG\033[38;2;164;195;89mG\033[38;2;167;199;90mb\033[38;2;170;203;91mY\033[38;2;167;198;90mZ\033[38;2;165;198;90mZ\033[38;2;170;203;91mYY\033[38;2;164;196;90mZ\033[38;2;164;196;89mZ\033[38;2;164;180;85mX\033[0m           \033[38;2;115;159;73mq\033[38;2;115;158;72mm\033[38;2;117;162;73mq\033[38;2;114;158;73mm\033[38;2;111;154;72m66\033[38;2;110;153;72m6\033[38;2;111;157;72mm\033[38;2;113;162;73mq\033[38;2;108;154;71m6\033[38;2;106;154;71mp\033[38;2;98;136;72m3\033[0m           \033[0m
                \033[38;2;133;170;77mV\033[38;2;131;167;76mh\033[38;2;130;167;76mh\033[38;2;130;165;75mhh\033[38;2;134;172;77mV\033[38;2;143;184;79mE\033[38;2;130;165;76mh\033[38;2;131;167;75mh\033[38;2;130;164;77mh\033[38;2;120;120;81m3\033[0m         \033[38;2;150;196;85mP\033[38;2;162;195;88mG\033[38;2;164;193;89mG\033[38;2;163;193;89mG\033[38;2;163;195;89mG\033[38;2;164;196;89mZ\033[38;2;163;195;89mG\033[38;2;153;182;89mX\033[0m          \033[38;2;121;169;72mg\033[38;2;120;162;73mq\033[38;2;118;159;73mq\033[38;2;116;158;73mm\033[38;2;119;163;74mS\033[38;2;113;156;72mm\033[38;2;112;156;72mmm\033[38;2;115;160;73mq\033[38;2;115;162;73mq\033[38;2;111;156;72m6\033[38;2;109;154;72m6\033[38;2;105;154;69mp\033[0m             \033[0m
                   \033[38;2;98;98;98mn\033[38;2;120;156;72mm\033[38;2;129;162;75mg\033[38;2;128;165;75mg\033[38;2;129;164;75mg\033[38;2;129;167;75mh\033[38;2;131;167;76mh\033[38;2;133;168;77mh\033[38;2;135;170;77mV\033[38;2;131;168;77mh\033[0m          \033[38;2;177;212;98mO\033[38;2;167;192;91mG\033[0m          \033[38;2;122;167;74mg\033[38;2;121;162;73mS\033[38;2;120;160;73mq\033[38;2;119;159;73mq\033[38;2;121;165;74mg\033[38;2;120;164;74mS\033[38;2;116;158;73mm\033[38;2;115;157;73mm\033[38;2;117;159;73mq\033[38;2;119;165;74mS\033[38;2;113;156;72mm\033[38;2;113;157;72mmm\033[38;2;114;156;70mm\033[0m               \033[0m
                  \033[38;2;150;180;83mE\033[38;2;152;186;83mX\033[38;2;151;184;83mg\033[38;2;150;184;82mg\033[38;2;147;180;83mE\033[38;2;152;178;83mE\033[38;2;150;180;85mg\033[38;2;136;160;77mh\033[38;2;129;164;75mg\033[38;2;139;177;79m4\033[38;2;136;165;76mh\033[0m                \033[38;2;255;255;98mW\033[38;2;127;173;76mV\033[38;2;123;165;76mg\033[38;2;124;163;75mg\033[38;2;123;162;74mS\033[38;2;123;160;74mS\033[38;2;122;160;74mS\033[38;2;124;165;75mg\033[38;2;125;168;75mh\033[38;2;120;162;74mS\033[38;2;119;159;74mq\033[38;2;120;163;74mS\033[38;2;121;167;75mg\033[38;2;118;160;74mq\033[38;2;115;158;73mm\033[38;2;114;158;73mm\033[38;2;111;156;72mm\033[38;2;136;136;72mp\033[0m                 \033[0m
                   \033[38;2;141;173;84m4\033[38;2;150;180;83mE\033[38;2;149;181;83mg\033[38;2;147;181;82mE\033[38;2;145;178;81mE\033[38;2;144;177;81m4\033[38;2;143;177;81m44\033[38;2;142;176;80m4\033[38;2;141;176;79m4\033[38;2;141;174;79m4\033[38;2;139;176;79m4\033[38;2;139;172;79md\033[38;2;140;173;78md\033[38;2;133;170;78mV\033[38;2;133;168;77mh\033[38;2;136;169;78mV\033[38;2;131;169;76mh\033[38;2;134;167;77mh\033[38;2;131;163;76mg\033[38;2;133;167;76mh\033[38;2;131;167;76mh\033[38;2;130;165;76mh\033[38;2;129;163;75mg\033[38;2;128;164;75mg\033[38;2;128;163;75mg\033[38;2;128;164;75mg\033[38;2;126;163;75mg\033[38;2;125;163;75mg\033[38;2;129;169;76mh\033[38;2;129;170;76mh\033[38;2;127;168;76mh\033[38;2;124;165;75mg\033[38;2;124;164;75mg\033[38;2;125;168;75mh\033[38;2;124;168;75mg\033[38;2;118;158;73mq\033[38;2;118;159;73mq\033[38;2;118;160;73mq\033[38;2;120;163;73mS\033[38;2;112;150;75m6\033[0m                    \033[0m
                      \033[38;2;156;177;81mE\033[38;2;150;184;83mg\033[38;2;146;178;82mE\033[38;2;144;178;81mE\033[38;2;143;177;81m4\033[38;2;151;186;83mX\033[38;2;157;196;85mG\033[38;2;156;196;84mG\033[38;2;153;192;83mP\033[38;2;150;188;82mX\033[38;2;145;184;81mg\033[38;2;143;178;80m4\033[38;2;140;176;79m4\033[38;2;139;173;79md\033[38;2;136;173;78md\033[38;2;136;172;78mV\033[38;2;136;173;78md\033[38;2;138;174;78mdd\033[38;2;138;176;78mdd\033[38;2;136;176;77md\033[38;2;135;174;77md\033[38;2;133;172;77mV\033[38;2;132;172;76mV\033[38;2;131;170;76mV\033[38;2;131;172;76mV\033[38;2;130;170;76mh\033[38;2;125;165;75mg\033[38;2;123;160;74mS\033[38;2;122;160;74mS\033[38;2;120;162;74mS\033[38;2;121;162;73mS\033[38;2;120;162;75mS\033[38;2;136;188;72mE\033[0m                       \033[0m
                          \033[38;2;140;182;82mE\033[38;2;144;181;82mE\033[38;2;142;178;81m4\033[38;2;143;177;81m4\033[38;2;141;174;80m4\033[38;2;139;173;79md\033[38;2;139;172;79md\033[38;2;136;170;78mVV\033[38;2;138;173;78md\033[38;2;140;176;79m44\033[38;2;139;176;78m4\033[38;2;138;174;78md\033[38;2;136;173;78md\033[38;2;134;170;77mV\033[38;2;131;168;76mh\033[38;2;128;164;75mgg\033[38;2;127;164;75mg\033[38;2;126;163;75mg\033[38;2;126;164;75mg\033[38;2;125;163;75mg\033[38;2;125;164;75mg\033[38;2;124;162;74mS\033[38;2;125;160;73mS\033[38;2;120;177;81mV\033[0m                           \033[0m
                               \033[38;2;160;255;98mU\033[38;2;136;169;79mV\033[38;2;136;172;80md\033[38;2;140;172;78md\033[38;2;133;172;78mV\033[38;2;134;168;78mV\033[38;2;132;170;77mV\033[38;2;132;169;77mVV\033[38;2;131;165;76mh\033[38;2;132;165;76mh\033[38;2;130;164;75mg\033[38;2;126;164;77mg\033[38;2;130;168;75mh\033[38;2;131;165;75mh\033[38;2;160;160;98m4\033[0m                                 \033[0m

\033[1;32m  A R G U S\033[0m
\033[90m  Security Scanner \u2014 See Everything\033[0m
"""

# Schema URL version is managed by release-it during releases
_SCHEMA_VERSION = "0.7.0"
_SCHEMA_URL = (
    "https://raw.githubusercontent.com/huntridge-labs/argus/"
    f"{_SCHEMA_VERSION}/argus-config.schema.json"
)
_DOCS_URL = "https://huntridge-labs.github.io/argus/"

# Exit codes (mirrors cli.py)
EXIT_SUCCESS = 0
EXIT_ERROR = 2


def run_init(
    platform: str = "none",
    force: bool = False,
    detect: bool = True,
    target_dir: str = ".",
) -> int:
    """Run the init workflow: detect, generate config, optionally generate CI.

    Returns an exit code (0 = success, 2 = error).
    """
    root = Path(target_dir)
    config_path = root / "argus.yml"

    # Show banner on interactive terminals with scroll effect
    if sys.stderr.isatty():
        import time
        for line in _BANNER.splitlines():
            print(line, file=sys.stderr)
            time.sleep(0.03)

    if config_path.exists() and not force:
        print(
            f"argus.yml already exists at {config_path}.\n"
            "Use --force to overwrite.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Detect project signals
    signals = detect_project(root) if detect else {}

    # Generate config content
    config_content = generate_config(signals)
    config_path.write_text(config_content, encoding="utf-8")
    print(f"Created {config_path}")

    # Generate CI workflow if requested
    ci_created = False
    if platform == "github":
        ci_created = _generate_github_workflow(root)

    # Print summary
    _print_summary(signals, config_path, platform, ci_created)

    return EXIT_SUCCESS


def detect_project(root: Path) -> dict[str, list[str]]:
    """Scan the project directory for language and framework signals.

    Returns a dict mapping signal names to lists of evidence paths.
    """
    signals: dict[str, list[str]] = {}

    python_patterns = list(root.rglob("*.py"))
    if python_patterns:
        signals["python"] = [str(p.relative_to(root)) for p in python_patterns[:5]]

    for manifest in ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
        matches = list(root.glob(manifest))
        if matches:
            signals.setdefault("node", []).extend(
                str(p.relative_to(root)) for p in matches
            )

    for lockfile in [
        "requirements.txt", "requirements-*.txt", "poetry.lock",
        "Pipfile.lock", "go.sum", "Cargo.lock", "Gemfile.lock",
        "composer.lock",
    ]:
        matches = list(root.glob(lockfile))
        if matches:
            signals.setdefault("dependencies", []).extend(
                str(p.relative_to(root)) for p in matches
            )

    # Also check for package-lock.json as a dependency signal
    for manifest in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
        matches = list(root.glob(manifest))
        if matches:
            signals.setdefault("dependencies", []).extend(
                str(p.relative_to(root)) for p in matches
                if str(p.relative_to(root)) not in signals.get("dependencies", [])
            )

    dockerfile_patterns = list(root.rglob("Dockerfile*"))
    compose_patterns = list(root.rglob("docker-compose*.yml")) + list(
        root.rglob("docker-compose*.yaml")
    )
    if dockerfile_patterns or compose_patterns:
        signals["container"] = [
            str(p.relative_to(root))
            for p in (dockerfile_patterns + compose_patterns)[:5]
        ]

    tf_files = list(root.rglob("*.tf"))
    k8s_dirs = [
        d for d in root.iterdir()
        if d.is_dir() and d.name in ("infrastructure", "terraform", "k8s", "kubernetes", "deploy")
    ]
    if tf_files or k8s_dirs:
        evidence = [str(p.relative_to(root)) for p in tf_files[:3]]
        evidence.extend(str(d.relative_to(root)) for d in k8s_dirs)
        signals["iac"] = evidence

    gh_workflows = root / ".github" / "workflows"
    if gh_workflows.is_dir():
        workflow_files = list(gh_workflows.glob("*.yml")) + list(
            gh_workflows.glob("*.yaml")
        )
        if workflow_files:
            signals["github-actions"] = [
                str(p.relative_to(root)) for p in workflow_files[:5]
            ]

    return signals


def generate_config(signals: dict[str, list[str]]) -> str:
    """Generate argus.yml content based on detected signals."""
    lines = [
        f"# yaml-language-server: $schema={_SCHEMA_URL}",
        "# Argus Security Scanner Configuration",
        f"# Docs: {_DOCS_URL}",
        "# Generated by: argus init",
        "",
        'version: "1.0"',
        "",
        "scanners:",
    ]

    # Always-enabled scanners
    lines.append("  # Secret detection — always recommended")
    lines.append("  gitleaks:")
    lines.append("    enabled: true")
    lines.append("")

    # Python detection
    if "python" in signals:
        evidence = signals["python"][0]
        lines.append(f"  # Detected: Python files found ({evidence})")
        lines.append("  bandit:")
        lines.append("    enabled: true")
        lines.append('    path: "."')
        lines.append("")
    else:
        lines.append("  # bandit:")
        lines.append("  #   enabled: true  # Enable for Python projects")
        lines.append('  #   path: "."')
        lines.append("")

    # Dependency scanning
    if "dependencies" in signals or "node" in signals:
        dep_evidence = (
            signals.get("dependencies", []) + signals.get("node", [])
        )
        evidence = dep_evidence[0] if dep_evidence else "manifests"
        lines.append(f"  # Detected: dependency manifests found ({evidence})")
        lines.append("  osv:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # osv:")
        lines.append("  #   enabled: true  # Enable for dependency vulnerability scanning")
        lines.append("")

    # Multi-language SAST
    lines.append("  # Multi-language pattern-based SAST")
    lines.append("  opengrep:")
    lines.append("    enabled: true")
    lines.append('    path: "."')
    lines.append("")

    # Supply chain
    if "github-actions" in signals:
        evidence = signals["github-actions"][0]
        lines.append(f"  # Detected: GitHub Actions workflows ({evidence})")
        lines.append("  supply-chain:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # supply-chain:")
        lines.append("  #   enabled: true  # Enable if using GitHub Actions")
        lines.append("")

    # IaC scanning
    if "iac" in signals:
        evidence = signals["iac"][0]
        lines.append(f"  # Detected: infrastructure-as-code files ({evidence})")
        lines.append("  trivy-iac:")
        lines.append("    enabled: true")
        lines.append(f'    path: "{_guess_iac_path(signals)}"')
        lines.append("")
        lines.append("  checkov:")
        lines.append("    enabled: true")
        lines.append(f'    path: "{_guess_iac_path(signals)}"')
        lines.append("")
    else:
        lines.append("  # trivy-iac:")
        lines.append("  #   enabled: true  # Enable for Terraform/Kubernetes")
        lines.append('  #   path: "infrastructure"')
        lines.append("")
        lines.append("  # checkov:")
        lines.append("  #   enabled: true  # Enable for infrastructure policy checks")
        lines.append('  #   path: "infrastructure"')
        lines.append("")

    # Container scanning
    if "container" in signals:
        evidence = signals["container"][0]
        lines.append(f"  # Detected: container files ({evidence})")
        lines.append("  # Run with: argus scan container --discover")
        lines.append("  container:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # container:")
        lines.append("  #   enabled: true  # Enable for Docker image scanning")
        lines.append("  #   image_ref: \"myapp:latest\"")
        lines.append("")

    # DAST (always commented — requires target)
    lines.append("  # zap:")
    lines.append("  #   enabled: true  # Enable for web application DAST")
    lines.append("  #   target_url: \"http://localhost:3000\"")
    lines.append("")

    # Malware (always commented — opt-in)
    lines.append("  # clamav:")
    lines.append("  #   enabled: true  # Enable for malware scanning")
    lines.append('  #   path: "."')
    lines.append("")

    # Reporting section
    lines.extend([
        "reporting:",
        "  formats:",
        "    - terminal",
        "    - sarif",
        "  severity_threshold: high",
        '  output_dir: "./argus-results"',
        "",
        "execution:",
        "  backend: auto",
        "  pull_policy: if-not-present",
        "",
    ])

    return "\n".join(lines)


def _guess_iac_path(signals: dict[str, list[str]]) -> str:
    """Guess the IaC root path from detected signals."""
    iac_evidence = signals.get("iac", [])
    for path_str in iac_evidence:
        parts = Path(path_str).parts
        if parts and parts[0] in (
            "infrastructure", "terraform", "k8s", "kubernetes", "deploy"
        ):
            return parts[0]
    return "."


def _generate_github_workflow(root: Path) -> bool:
    """Generate a minimal GitHub Actions security scanning workflow.

    Returns True if the file was created, False if it already exists.
    Never overwrites an existing workflow file.
    """
    workflows_dir = root / ".github" / "workflows"
    workflow_path = workflows_dir / "security-scan.yml"

    if workflow_path.exists():
        print(f"  Skipped: {workflow_path} already exists")
        return False

    workflows_dir.mkdir(parents=True, exist_ok=True)

    content = """\
# Argus Security Scanning
# Generated by: argus init
# Docs: https://huntridge-labs.github.io/argus/
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Argus
        run: pip install pyyaml

      - name: Run security scan
        run: python -m argus scan --severity-threshold high
"""
    workflow_path.write_text(content, encoding="utf-8")
    print(f"Created {workflow_path}")
    return True


def _print_summary(
    signals: dict[str, list[str]],
    config_path: Path,
    platform: str,
    ci_created: bool,
) -> None:
    """Print a summary of what was created and next steps."""
    print()
    print("Argus initialized!")
    print()

    if signals:
        print("Detected:")
        signal_labels = {
            "python": "Python source files",
            "node": "Node.js project",
            "dependencies": "Dependency manifests",
            "container": "Container/Docker files",
            "iac": "Infrastructure as code",
            "github-actions": "GitHub Actions workflows",
        }
        for key, evidence in signals.items():
            label = signal_labels.get(key, key)
            print(f"  - {label} ({evidence[0]})")
        print()

    print("Next steps:")
    print(f"  1. Review {config_path} and adjust scanner settings")
    print("  2. Run: argus validate")
    print("  3. Run: argus scan")
    if platform == "github" and ci_created:
        print("  4. Commit .github/workflows/security-scan.yml")
    elif platform == "github" and not ci_created:
        print("  4. Review existing .github/workflows/security-scan.yml")
    print()
    print(f"Docs: {_DOCS_URL}")
