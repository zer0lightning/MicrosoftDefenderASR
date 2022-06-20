# Microsoft Defender ASR Script
https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide

Attack surface reduction rules overview
Article
05/18/2022
6 minutes to read
14 contributors


Applies to:

Microsoft Defender for Endpoint Plan 2
Microsoft 365 Defender
Microsoft Defender Antivirus
Platforms

Windows
Why attack surface reduction rules are important
Your organization's attack surface includes all the places where an attacker could compromise your organization's devices or networks. Reducing your attack surface means protecting your organization's devices and network, which leaves attackers with fewer ways to perform attacks. Configuring attack surface reduction rules in Microsoft Defender for Endpoint can help!

Attack surface reduction rules target certain software behaviors, such as:

Launching executable files and scripts that attempt to download or run files
Running obfuscated or otherwise suspicious scripts
Performing behaviors that apps don't usually initiate during normal day-to-day work
Such software behaviors are sometimes seen in legitimate applications. However, these behaviors are often considered risky because they are commonly abused by attackers through malware. Attack surface reduction rules can constrain software-based risky behaviors and help keep your organization safe.

For more information about configuring attack surface reduction rules, see Enable attack surface reduction rules.

Assess rule impact before deployment
You can assess how an attack surface reduction rule might affect your network by opening the security recommendation for that rule in threat and vulnerability management.

The ASR recommendation

In the recommendation details pane, check for user impact to determine what percentage of your devices can accept a new policy enabling the rule in blocking mode without adversely affecting productivity.

See Requirements in the "Enable attack surface reduction rules" article for information about supported operating systems and additional requirement information.

Audit mode for evaluation
Use audit mode to evaluate how attack surface reduction rules would affect your organization if enabled. Run all rules in audit mode first so you can understand how they affect your line-of-business applications. Many line-of-business applications are written with limited security concerns, and they might perform tasks in ways that seem similar to malware. By monitoring audit data and adding exclusions for necessary applications, you can deploy attack surface reduction rules without reducing productivity.

Warn mode for users
(NEW!) Prior to warn mode capabilities, attack surface reduction rules that are enabled could be set to either audit mode or block mode. With the new warn mode, whenever content is blocked by an attack surface reduction rule, users see a dialog box that indicates the content is blocked. The dialog box also offers the user an option to unblock the content. The user can then retry their action, and the operation completes. When a user unblocks content, the content remains unblocked for 24 hours, and then blocking resumes.

Warn mode helps your organization have attack surface reduction rules in place without preventing users from accessing the content they need to perform their tasks.

Requirements for warn mode to work
Warn mode is supported on devices running the following versions of Windows:

Windows 10, version 1809 or later
Windows 11
Windows Server, version 1809 or later
Microsoft Defender Antivirus must be running with real-time protection in Active mode.

Also, make sure Microsoft Defender Antivirus and antimalware updates are installed.

Minimum platform release requirement: 4.18.2008.9
Minimum engine release requirement: 1.1.17400.5
For more information and to get your updates, see Update for Microsoft Defender antimalware platform.

Cases where warn mode is not supported
Warn mode isn't supported for three attack surface reduction rules when you configure them in Microsoft Endpoint Manager. (If you use Group Policy to configure your attack surface reduction rules, warn mode is supported.) The three rules that do not support warn mode when you configure them in Microsoft Endpoint Manager are as follows:

Block JavaScript or VBScript from launching downloaded executable content (GUID d3e037e1-3eb8-44c8-a917-57927947596d)
Block persistence through WMI event subscription (GUID e6db77e5-3df2-4cf1-b95a-636979351e5b)
Use advanced protection against ransomware (GUID c1db55ab-c21a-4637-bb3f-a12568109d35)
Also, warn mode isn't supported on devices running older versions of Windows. In those cases, attack surface reduction rules that are configured to run in warn mode will run in block mode.

Notifications and alerts
Whenever an attack surface reduction rule is triggered, a notification is displayed on the device. You can customize the notification with your company details and contact information.

Also, when certain attack surface reduction rules are triggered, alerts are generated.

Notifications and any alerts that are generated can be viewed in the Microsoft 365 Defender portal.

For specific details about notification and alert functionality, see: Per rule alert and notification details, in the article Attack surface reduction rules reference.

Advanced hunting and attack surface reduction events
You can use advanced hunting to view attack surface reduction events. To streamline the volume of incoming data, only unique processes for each hour are viewable with advanced hunting. The time of an attack surface reduction event is the first time that event is seen within the hour.

For example, suppose that an attack surface reduction event occurs on 10 devices during the 2:00 PM hour. Suppose that the first event occurred at 2:15, and the last at 2:45. With advanced hunting, you'll see one instance of that event (even though it actually occurred on 10 devices), and its timestamp will be 2:15 PM.

For more information about advanced hunting, see Proactively hunt for threats with advanced hunting.

Attack surface reduction features across Windows versions
You can set attack surface reduction rules for devices that are running any of the following editions and versions of Windows:

Windows 10 Pro, version 1709 or later

Windows 10 Enterprise, version 1709 or later

Windows Server, version 1803 (Semi-Annual Channel) or later

Windows Server 2019

Windows Server 2016

Windows Server 2012 R2
