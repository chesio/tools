#!/usr/bin/env python
#
# Benchie - benchmarking tool for Unix environments that can measure
# wall clock time, CPU time and virtual memory peak of particular
# process and all its subprocesses.
#
# ---------------------------------------------------------------------
#
# Session benchmarking
# ====================
#
# Benchie is capable not only of producing a global benchmarking info
# (i.e. a total wall clock and CPU time and VM peak of the whole tree
# of processes), but also deliver a benchmarking info of a user-defined
# session. This is convenient, if the procedure you are measuring
# proceeds through several different steps and you would like to have
# a separate benchmarking info for each of these steps. To mark the
# beginning of a new session, just fill its name in session management
# file, to stop it, either fill a new session name or make it blank.
# The session management file is looked for in the benchmarking direc-
# tory.
#
# Important note: the implementation expects that during session change
# only root process is alive (all subprocesses of old session have
# finished before change and no subprocess of new session have started
# yet). The reason is that CPU time of a particular subprocess is
# accounted to active session in the moment the subprocess terminates,
# thus CPU time of all subprocesses alive in the moment of session
# change will be entirely (and incorrectly) accounted to a new session.
#
# Stopping the benchmarker
# ========================
#
# Benchie will stop automatically as soon as root process perishes
# (there is no /proc/[root_pid] directory).
#
# You may use a stop file to explicitly stop the benchmarking, but in
# such case all subprocesses must finish before stopfile is set,
# otherwise their CPU time will not be accounted into any session (not
# even the global session). The stopfile is looked for in the bench-
# marking directory.
#
# As a consequence of the above, CPU time of root process is tracked
# only within the global session and may contain the additional amount
# of CPU time consumed just after stopfile was set.
#
# Credits
# =======
#
# (C) Ceslav Przywara 2013, ceslav@przywara.cz

from __future__ import division

import json
import os
import os.path
import platform
import re
import subprocess
import sys
import time

from optparse import OptionParser


USAGE = """
%prog [options] benchmarking-dir ppid
  benchmarking-dir  -- directory, where to save the output files
  ppid              -- PID of the root process to benchmark"""
VERSION = "1.2.0"

#-- Files produced by benchmarker
PLATFORM_FILE_SUFFIX = ".plaftorm" # Information about the machine and OS
LOG_FILE_SUFFIX = ".log" # Full session log
SUMMARY_FILE_SUFFIX = ".summary" # Brief session summary
JSON_FILE_SUFFIX = ".json" # summary as JSON (for easier parsing)
DONE_FILE_SUFFIX = ".done" # Touched just before exit

#-- Files used for communication with benchmarker
STOP_FILE = "stop" # ~ stop benchmarking
SESSION_MANAGEMENT_FILE = "session" # ~ start session with name from file

VM_SIZE_UNITS = 'kB'
VM_SIZE_REGEX = re.compile('VmSize:\s+(\d+)\s%s' % VM_SIZE_UNITS)


#### MAIN ##############################################################

def main(options, args):

	log_dir = args[0]
	root_pid = int(args[1])

	if not os.path.isdir(log_dir):
		return "error: directory %s does not exist!" % log_dir
	# end of if

	stopFilename = os.path.join(log_dir, STOP_FILE)
	smFilename = os.path.join(log_dir, SESSION_MANAGEMENT_FILE)

	if os.path.isfile(stopFilename):
		return "error: log directory contains stop file, remove file %s to continue!" % stopFilename
	# end of if

	platformFile = open(os.path.join(log_dir, options.prefix + PLATFORM_FILE_SUFFIX), 'w')
	logFile = open(os.path.join(log_dir, options.prefix + LOG_FILE_SUFFIX), 'w')
	summaryFile = open(os.path.join(log_dir, options.prefix + SUMMARY_FILE_SUFFIX), 'w')
	jsonFile = open(os.path.join(log_dir, options.prefix + JSON_FILE_SUFFIX), 'w')
	doneFile = open(os.path.join(log_dir, options.prefix + DONE_FILE_SUFFIX), 'w')

	#-- Finish initialization

	# dictionary of running processes
	running = {}
	# pid of benchmarker
	my_pid = os.getpid()

	#---- Processing

	#-- Start session
	logFile.write('%s Benchmarking of process %d childs started.\n' % (timestamp(), root_pid))
	globalSession = GlobalSession() # Global wallclock starts running now.

	#-- Main benchmarking loop.
	while 1: # NB: Empirically faster than "while True".

		_running = {} # Running in current loop { pid: process }
		_started = [] # Started in current loop [ process, ... ]

		# Returns empty list, if process with @root_pid is no longer running.
		ptree = getProcessTree(root_pid, options.excluding_root)

		for pid, ppid, distance in ptree:

			if pid == my_pid: continue

			process = running.get(pid)

			if process:
				# Have been already running
				_running[pid] = process
				del running[pid] # !
			else:
				# New one found
				process = Process(pid, ppid, distance, getCommand(pid))
				_running[pid] = process
				_started.append(process)
			# end of if

			# Update current VM size and CPU ticks used so far.
			process.update()

		# end of for

		# Those that were *running*, but are not *_running*, are *finished*.
		finished = running

		#-- It is important to stick to the following processing order:
		# 1) Process cpu ticks of *finished* processes (and log them),
		# 	as they belong to any named sessions that have been active
		#	so far (and may not be active after the following step).
		# 2) Check, if we should continue benchmarking or the stopping
		#	condition has been detected.
		# 2) Update active named sessions if requested.
		# 3) Process VM size of *running* processes and log any freshly
		#	started processes, as they belong to currently running
		#	named sessions.
		# 4) Go to sleep.

		# Get CPU ticks that have been used by *finished* processes.
		cpu_ticks = sum(process.cpu_ticks for process in finished.itervalues())
		# Update CPU ticks:
		globalSession.updateCpuTicks(cpu_ticks)

		# Log finished processes.
		for process in finished.itervalues():
			logFile.write('%s Benchmarked process finished.\n' % timestamp())
			logProcess(logFile, process)
		# end of for

		# Stop benchmarking?
		if os.path.isfile(stopFilename) or not isProcRunning(root_pid):
			# Explicit or implicit stop.
			if not options.excluding_root and root_pid in _running:
				# Root process was still *unfinished* above:
				# we have to explicitly update global session with its
				# CPU time and log it as finished:
				process = _running[root_pid]
				Session.updateCpuTicks(globalSession, process.cpu_ticks)
				logFile.write('%s Benchmarked process finished.\n' % timestamp())
				logProcess(logFile, process)
			# end of if
			break
		# end of if

		# Those that are *_running* are really *running*.
		running = _running

		# Named session update?
		if os.path.isfile(smFilename):
			with open(smFilename, 'r') as smFile:
				pathname = smFile.read().rstrip()
			# end of with
			logFile.write('%s Session "%s" started.\n' % (timestamp(), pathname))
			globalSession.activate(pathname)
			os.unlink(smFilename)
		# end of if

		# Log started processes.
		for process in _started:
			logFile.write('%s Benchmarked process started.\n' % timestamp())
			logProcess(logFile, process, brief=True)
		# end of for

		# Get current VM usage by *running* processes.
		vm_size = sum(process.vm_size for process in running.itervalues())
		# Update VM peak.
		globalSession.updateVmPeak(vm_size)

		# Sleep for a while.
		time.sleep(options.sleep)

	# end of while

	#-- Finish session
	globalSession.end()
	logFile.write('%s Benchmarking of process %d childs finished!\n' % (timestamp(), root_pid))

	#-- Write benchmarker consumption to done file
	doneFile.write('Benchmarker run with %s interval and consumed %.02f CPU seconds.\n' % (options.sleep, time.clock()))

	#-- Write session data to summary file
	logSession(summaryFile, globalSession) # global + named
	for session in globalSession: logSession(summaryFile, session)

	#-- Write summary also to JSON file.
	writeJSONSummary(jsonFile, globalSession)

	#-- Write host file info
	# node name: chestryna
	platformFile.write(platform.node() + '\n')
	# machine type: x86_64
	platformFile.write(platform.machine() + '\n')
	# release (on Linux this is kernel version): 3.2.0-43-generic
	platformFile.write(platform.release() + '\n')
	# linux distribution:  ('Ubuntu', '12.04', 'precise')
	platformFile.write(' '.join(platform.linux_distribution()) + '\n')
	# human readable summary: 'Linux-3.2.0-43-generic-x86_64-with-Ubuntu-12.04-precise'
	platformFile.write(platform.platform() + '\n')

	#-- Final clean up:
	if os.path.isfile(stopFilename): os.unlink(stopFilename)
	# :)
	map(file.close, (platformFile, logFile, summaryFile, jsonFile, doneFile))

	return 0

# end of def


#### Classes ###########################################################

class Process(object):

	def __init__(self, pid, ppid, distance, command):
		self.pid = pid
		self.ppid = ppid
		self.distance = distance
		self.command = command
		self.cpu_ticks_start = getCpuTicks(pid) # Number of CPU ticks at start.
		self.cpu_ticks_total = 0
		self.vm_size = 0
		self.vm_peak = 0
	# end of def

	@property
	def cpu_ticks(self):
		# Number of CPU ticks consumed while benchmarking:
		return self.cpu_ticks_total - self.cpu_ticks_start
	# end of def

	@property
	def cpu_time(self):
		return ticks2seconds(self.cpu_ticks)
	# end of def

	def update(self):
		# VM size
		vm_size = getVmUsed(self.pid) # Might be 0.
		self.vm_size = vm_size
		if vm_size > self.vm_peak: self.vm_peak = vm_size
		# end of if

		# CPU time
		cpu_ticks = getCpuTicks(self.pid)
		if cpu_ticks > 0:
			self.cpu_ticks_total = cpu_ticks
		# end of if
	# end of def

# end of class


class Session(object):

	def __init__(self, name):
		self.name = name
		self.started = time.time()
		self.ended = None
		self.vm_peak = 0
		self.cpu_ticks = 0
	# end of def

	@property
	def cpu_time(self):
		return ticks2seconds(self.cpu_ticks)
	# end of def

	@property
	def wallclock(self):
		return self.ended - self.started
	# end of def

	def end(self):
		self.ended = time.time()
	# end of def

	def updateCpuTicks(self, cpu_ticks):
		self.cpu_ticks += cpu_ticks
	# end of def

	def updateVmPeak(self, vm_size):
		self.vm_peak = max(self.vm_peak, vm_size)
	# end of def

# end of class


class GlobalSession (Session):

	PATHNAME_SEP = '/'

	def __init__(self):
		Session.__init__(self, 'GLOBAL')
		self.sessions = {} # Sessions: { tag: session }
		self.active = set() # Set of tags of currently active sessions
		self.order = [] # List of session tags in order of appearence
	# end of def

	def __getitem__(self, tag):
		"""
		Get named session by its @tag.
		"""
		return self.sessions[tag]
	# end of def

	def __iter__(self):
		for tag in self.order:
			yield self.sessions[tag]
		# end of for
	# end of def

	def activate(self, pathname):

		was_active = self.active.copy()
		new = [] # List of brand new sessions.

		while pathname:

			if pathname in was_active:
				was_active.remove(pathname) # Still active.
			else:
				# Session cannot be reactivated, so ignore pathname
				# if it marks existing, but already terminated session.
				if pathname not in self.sessions:
					# Ok, new session pathname, create and make active:
					self.sessions[pathname] = Session(pathname)
					self.active.add(pathname)
					new.append(pathname)
				# end of if

			# end of if

			# Update pathname.
			sep_pos = pathname.rfind(self.PATHNAME_SEP)
			if sep_pos < 0: pathname = ''
			else: pathname = pathname[:sep_pos]

		# end of while

		for tag in was_active:
			# Session not active anymore.
			self.sessions[tag].end()
			self.active.remove(tag)
		# end of for

		# We want "main-session" to preceed "main-session/sub-session",
		self.order += reversed(new) # ...therefore reversed.

	# end of def

	def end(self):
		for tag in self.active:
			self.sessions[tag].end()
		# end of for
		self.active = set()
		self.ended = time.time()
	# end of def

	def updateCpuTicks(self, cpu_ticks):
		self.cpu_ticks += cpu_ticks
		# Update also all active named sessions:
		for tag in self.active:
			self.sessions[tag].updateCpuTicks(cpu_ticks)
		# end of for
	# end of def

	def updateVmPeak(self, vm_size):
		self.vm_peak = max(self.vm_peak, vm_size)
		# Update also all active named sessions:
		for tag in self.active:
			self.sessions[tag].updateVmPeak(vm_size)
		# end of for
	# end of def

# end of class


#### Helpers ###########################################################


def seconds2hhmmss(seconds, format='%02d:%02d:%02d'):
	seconds = int(seconds) # Remove possible floatiness
	minutes = seconds // 60 # 123 // 60 = 2 ~ __future__ integer division
	return format % (minutes // 60, minutes % 60, seconds % 60)
# end of def


def timestamp():
	return time.strftime('[%Y-%m-%d %H:%M:%S]')
# end of def


def logProcess(outFile, process, brief=False):
	outFile.write('  PID: %d\n' % process.pid)
	outFile.write('  PPID: %s (distance %d)\n' % (process.ppid, process.distance))
	outFile.write('  Command: %s\n' % process.command)
	if not brief:
		outFile.write('  VmPeak: %d kB\n' % process.vm_peak)
		outFile.write('  CPU time: %d ticks (%.02f secs ~ %s)\n' %
			(process.cpu_ticks, process.cpu_time, seconds2hhmmss(process.cpu_time))
		)
	# end of if
# end of def


def logSession(outFile, session):
	outFile.write('Session "%s":\n' % session.name)
	outFile.write('  VmPeak: %d kB\n' % session.vm_peak)
	outFile.write('  CPU time: %d ticks (%.02f secs ~ %s)\n' %
		(session.cpu_ticks, session.cpu_time, seconds2hhmmss(session.cpu_time))
	)
	outFile.write('  Wall-clock time: %.02f secs (~ %s)\n' %
		(session.wallclock, seconds2hhmmss(session.wallclock))
	)
# end of def


def jsonize(session):
	"""
	Wrap session data into dictionary object that is easy to dump into
	JSON format.
	"""

	return {
		"name": session.name,
		"cpu": {
			"ticks": session.cpu_ticks,
			"secs": session.cpu_time,
			"time": seconds2hhmmss(session.cpu_time)
		},
		"vm_peak": {
			"value": session.vm_peak,
			"units": VM_SIZE_UNITS
		},
		"wallclock": {
			"secs": session.wallclock,
			"time": seconds2hhmmss(session.wallclock)
		}
	}
# end of def


def writeJSONSummary(outFile, globalSession):

	# Global session first
	data = jsonize(globalSession)
	# Named sessions afterwards
	data["sessions"] = map(jsonize, globalSession)
	# Dump in the end
	json.dump(data, outFile, indent=2)

# end of def


#### OS related ########################################################


# Credits: http://stackoverflow.com/questions/4189123/python-how-to-get-number-of-mili-seconds-per-jiffy
def ticks2seconds(ticks):
	return ticks / os.sysconf('SC_CLK_TCK')
# end of def


# Credits: http://stackoverflow.com/questions/1158076/implement-touch-using-python
def touch(fname, times=None):
    with file(fname, 'a'):
        os.utime(fname, times)
    # end of with
# end of def


def getProcessChilds(pid):
	try:
		pids = check_output(("ps --ppid %d -o pid=" % pid).split())
		return map(int, pids.split())
	except subprocess.CalledProcessError:
		# ps return 1 if there are no results
		return []
	# end of try-except
# end of def


def getProcessDescendants(pid, distance=1):
	"""
	Retrieve the list of all descendants of process with @pid.
	Each item in list is triple (pid, ppid, distance from @pid)
	pid -- process id of root process
	distance -- distance from origin root process (default 1)
	"""
	childs = getProcessChilds(pid)
	populate = lambda child: (child, pid, distance)
	recurse = lambda child: getProcessDescendants(child, distance+1)
	return sum(map(recurse, childs), map(populate, childs))
# end of def


def getProcessTree(pid, excludeRoot = False):

	# Sanity check:
	if not isProcRunning(pid): return []

	# Exclude root, if requested, otherwise set its ppid to None and
	# distance to itself as 0.
	return ([] if excludeRoot else [(pid, None, 0)]) + getProcessDescendants(pid)

# end of def


def getCommand(pid):
	try:
		with open('/proc/%d/cmdline' % pid, 'r') as procCmdlineFile:
			return procCmdlineFile.read().replace('\00', ' ').strip()
		# end of with
	except:
		# Process might have died.
		return ''
	# end of try-except
# end of def


def getCpuTicks(pid):
	try:
		with open('/proc/%d/stat' % pid, 'r') as procStatFile:
			chunks = procStatFile.read().split()
			return int(chunks[13]) + int(chunks[14]) # utime + stime
		# end of with
	except:
		# Process might have died.
		return 0
	# end of try-except
# end of def


def getVmUsed(pid):
	try:
		with open('/proc/%d/status' % pid, 'r') as procStatusFile:
			for line in procStatusFile:
				match = re.match(VM_SIZE_REGEX, line)
				if match: return int(match.group(1))
			# end of for
		# end of with
		return 0
	except:
		# Process might have died.
		return 0
	# end of try-except
# end of def


def isProcRunning(pid):
	return os.path.isdir('/proc/%d' % pid)
# end of def


if sys.version_info[0] >= 2 and sys.version_info[1] >= 7:
	# Function check_output is available in module subprocess since Python 2.7
	# http://docs.python.org/2/library/subprocess.html#subprocess.check_output
	check_output = subprocess.check_output
else:
	# For Python older than 2.7 use backported implementation.
	# Credits: https://gist.github.com/edufelipe/1027906
	def check_output(*popenargs, **kwargs):
		"""
		Run command with arguments and return its output as a byte string.
		Backported from Python 2.7 as it's implemented as pure python on stdlib.
		"""
		process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
		output, unused_err = process.communicate()
		retcode = process.poll()
		if retcode:
			cmd = kwargs.get("args")
			if cmd is None: cmd = popenargs[0]
			error = subprocess.CalledProcessError(retcode, cmd)
			error.output = output
			raise error
		# end of if
		return output
	# end of def
# end of if


#### RUN main() ########################################################

if __name__ == "__main__":

	#---- Initialization
	parser = OptionParser(usage=USAGE, version=VERSION)

	parser.add_option("-s", "--sleep", type="float", default=1.0,
		help="time to sleep between measurements", metavar="SECONDS")
	parser.add_option("-p", "--prefix", default="benchie",
		help="prefix of output files")
	parser.add_option("-e", "--excluding-root", action="store_true", default=False,
		help="do NOT benchmark the root process itself, only its childs")

	(options, args) = parser.parse_args()

	if len(args) != 2:
		parser.error("incorrect number of arguments")
	# end of if

	try:
		sys.exit(main(options, args))
	except Exception, e:
		sys.exit(str(e))
	# end of try-except

# end of main
