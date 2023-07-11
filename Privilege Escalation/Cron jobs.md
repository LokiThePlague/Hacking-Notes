A *cron* job is a scheduled job on Unix/Linux systems that runs at a specific time or at regular time intervals. These jobs are defined in a *crontab* file that specifies which commands should be executed and when they should be executed.

Detection and exploitation of cron jobs is a technique used by attackers to elevate their level of access on a compromised system. For example, if an attacker detects that a file is being executed by the user "root" through a cron job that runs at regular time intervals, and realizes that the permissions defined in the file are misconfigured, he could manipulate the contents of the file to include malicious instructions which would be executed in a privileged way as the user 'root', since it corresponds to the user who is executing that file.

However, to detect cron jobs, attackers can use tools such as [Pspy](https://github.com/DominicBreuker/pspy). [Pspy](https://github.com/DominicBreuker/pspy) is a command line tool that monitors the jobs running in the background of a Unix/Linux system and displays new jobs that are started.

In order to reduce the chances of an attacker being able to exploit cron jobs on a system, it is recommended to do one of the following:

- *Limit the number of cron jobs*: it is important to limit the number of cron jobs running on the system and ensure that permissions are only granted to jobs that require special permissions to function properly. This decreases the attack surface and reduces the chances that an attacker can find a vulnerable cron job.
- *Verify cron job permissions*: It is important to review cron job permissions to ensure that only authorized users and groups are granted permissions. In addition, it is recommended to avoid granting superuser permissions to cron jobs unless strictly necessary.
- *Regularly monitor the system*: It is important to regularly monitor the system to detect unexpected changes in cron jobs and to look for possible security breaches. In addition, it is recommended to use security monitoring tools to detect suspicious activity on the system.
- *Configure cron job logs*: it is recommended to enable the logging option for cron jobs, to be able to identify any suspicious activity in the defined jobs and to be able to keep a record of the activities performed by each of these.

# Example