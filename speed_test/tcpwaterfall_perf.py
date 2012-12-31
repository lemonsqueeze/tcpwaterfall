#!/usr/bin/python

#@profile
def main():
    import sys;
    import re;
    import socket;
    from optparse import OptionParser

    ###########################################################
    # Default values

    # Diagram timescale in ms (= 1 char on screen)
    timescale_ms = 50

    # Time scale spacing (characters)
    scaleint = 10


    ###########################################################
    # Arg handling

    def usage():
        print \
    """Usage: tcpwaterfall [options] < capture_file | less -SR

      Display a waterfall diagram of tcp connections from tcpdump output.
      Open in your favorite editor, or less to makes it 4 way scrollable
      (use arrows to navigate the waterfall!)

      Generate capture file with something like:
        tcpdump -tt -s 500 -l -i any > capture_file          (-tt is important)
      To use wireshark capture, save in "wireshark/tcpdump/libpcap" format, and
        tcpdump -tt -s 500 -l -r wireshark_capture.pcap > capture_file
      (use -n if you don't want name resolution)

      Diagram scale:
        -t timescale  Set diagram's time scale in ms  (default {timescale_ms})
                      (1 char on screen = timescale ms)
        -w            Fit to term's width.
        -c cols       Number of columns to display output.

      Display etc:
        -l            Don't hide hostname for localhost.   (default: show port only)
        -z            Show packets without data (acks...)  (default: hidden)
        -r            Raw output, don't use colors.
        -d            Debug mode. Show packets ignored by the parser.

      Stream display  [: SYN flag
          format:     ]: FIN flag
                      O: SYN then FIN
                      I: FIN then SYN
                      #: packet with data
                      _: packet without data (ack...)
                      .: silence
    """.format(timescale_ms=timescale_ms)
        exit(1)


    parser = OptionParser(conflict_handler="resolve")
    parser.add_option("-h", "--help",
                      action="callback", callback=lambda a,b,c,d: usage())
    parser.add_option("-t", "--timescale",      dest="timescale_ms", default=timescale_ms)
    parser.add_option("-w", "--fit-width",      dest="fit_width", action="store_true")
    parser.add_option("-c", "--columns",        dest="columns")
    parser.add_option("-l", "--show-localhost", dest="show_localhost_src", action="store_true")
    parser.add_option("-z",                     dest="show_empty", action="store_true")
    parser.add_option("-r",                     dest="no_colors", action="store_true")
    parser.add_option("-d",                     dest="debug_mode", action="store_true")
    (options, args) = parser.parse_args()
    if (len(args) > 1):
        usage()

    dump_file = sys.stdin
    if (len(args)):
        dump_file = open(args[0], "r")

    timescale_ms = options.timescale_ms
    if options.fit_width:
        # my goodness, is this ugly ...
        from subprocess import Popen, PIPE
        options.columns = Popen(["tput", "cols"], stdout=PIPE).communicate()[0].strip()


    ###########################################################
    # processing

    packets = [];
    mintime = None;
    maxtime = 0.0;
    # Formatting: longest src
    max_src = 0

    def split_host_port(s):
        s = s.replace(':', '')
        return s.rsplit('.', 1)

    def split_host_port_stupid(s):
        s = s.replace(':', '')[::-1]
        rport, rhost = s.split('.', 1)
        return (rhost[::-1], rport[::-1])

    def split_host_port_stupid2(s):
        s = s.replace(':', '')
        f = s.split('.')
        n = len(f)
        host = '.'.join(f[:n-1])
        port = f[n-1]
        return (host, port)

    # tcpdump output parsing
#    exp = re.compile(r'(.*) IP (.*)\.([^.]*) > (.*)\.([^.]*): Flags \[(.*)\],.*, length (.*)')
    for line in dump_file:
# direct regexp
#        m = re.search(r'(.*) IP (.*)\.([^.]*) > (.*)\.([^.]*): Flags \[(.*)\],.*, length (.*)', line);

# compiled regexp
#        m = exp.search(line);
#        if m:
#            timestamp, src, sport, dst, dport, flags, length = m.groups();

        if (line.find("Flags") != -1):
            timestamp, _, source, _, dest, _, flags, _ = line.split(' ', 7);
            src, sport = split_host_port(source)
            dst, dport = split_host_port(dest)
            length=1 #hack
#            print src, sport, dst, dport


            timestamp = float(timestamp)
            length = int(length)

            if (not mintime):
                mintime = timestamp;
            maxtime = timestamp;
            if (len(src) > max_src):
                max_src = len(src)

            packets.append([timestamp, src, sport, dst, dport, flags, length]);
            continue

        if (options.debug_mode):
            print line.strip()

    if (options.debug_mode):
        exit(0)
    if (dump_file != sys.stdin):
        dump_file.close()

    timescale = float(timescale_ms) / 1000;
    line_head_len = max_src + 13                    # length of "n: src:port > " part
    if (options.columns):
        avail = int(options.columns) - line_head_len - 1
        if (avail > 5):
            timescale = (maxtime - mintime) / avail

    def pretty_float(fl):
        f = float(fl)
        if len(str(f - int(f))) > 5:
            return "%.3f" % (f)
        return str(f)


    print ("%i Packets, %ss Total. Timescale: %ims.\n" %
           (len(packets), pretty_float(maxtime - mintime), timescale * 1000))

    nslots = int((maxtime - mintime) / timescale) + 1
    timelines = ['dummy']  # start at index 1

    # Stream handling
    stream_nos = {}
    nos_stream = {}
    def stream_no(src, sport, dst, dport):
        id = "%s:%s:%s:%s" % (src, sport, dst, dport);
        # print "id: ", id;
        if id in stream_nos:
            return stream_nos[id];

        n = len(stream_nos) + 1;             # avoid n=0 as stream no
        stream_nos[id] = n;
        nos_stream[n] = id;
        timelines.append(['.'] * nslots);
    #    timelines.append(array.array('c', ['.'] * nslots));

        # add reverse direction as well
        stream_no(dst, dport, src, sport);
        return n

    # Fill in timeline data
    for p in packets:
        timestamp, src, sport, dst, dport, flags, length = p;
        n = stream_no(src, sport, dst, dport);
        timeline = timelines[n]
        slot = int((timestamp - mintime) / timescale);

        if (flags.find("S") != -1):         # SYN flag
            if timeline[slot] == "]":
                timeline[slot] = "I";    
            else:
                timeline[slot] = "[";

        if (flags.find("F") != -1):         # FIN flag
            if timeline[slot] == "[":
                timeline[slot] = "O";    
            else:
                timeline[slot] = "]";

        # Packet with data
        if (length > 0 and
            (timeline[slot] == "." or timeline[slot] == "_")):
            timeline[slot] = "#"

        # Anything else
        if (options.show_empty and timeline[slot] == "."):
            timeline[slot] = "_";

    # Replace "." with " " outside connection's lifespan
    def hide_outside(timeline):
        for i in range(len(timeline)):
            if timeline[i] != ".": break;
            timeline[i] = " ";

        for i in range(len(timeline)-1, -1, -1):
            if timeline[i] != ".": break;
            timeline[i] = " ";

    ################################################################################
    # Output

    colors = dict(wb = "\033[40;37;1m",      # white bold
                  rb = "\033[40;31;1m",      # red bold
                  yb = "\033[40;33;1m",      # yellow bold
                  pb = "\033[40;35;1m",      # purple bold
                  bb = "\033[40;34;1m",      # blue bold
                  cb = "\033[40;36;1m",      # cyan bold
                  e  = "\033[0m")            # end ansi color sequence
    def color(name):
        if (options.no_colors):
            return ""
        return colors[name]

    # Print scale
    s=""
    for i in range(0, nslots, scaleint):
        v = pretty_float(i * timescale)
        s += "%-*s" % (scaleint, v + "s");
    print "%*s%s" % (line_head_len, "Time: ", s);


    hostname = socket.gethostname();
    for i in range(1, len(timelines)):
        stream = nos_stream[i];
        src, sport, _ = stream.split(':', 2);

        col = color('yb');
        if (stream.find("localhost") != -1 or
            stream.find("127.0.0.1") != -1):
            col = color('bb');

        if (not options.show_localhost_src and
            (src == hostname or
             src == "localhost" or
             src == "127.0.0.1")):
            src = ""

        if (i % 2 == 1):
            s = "%02i: %*s:%-5s > " % ((i+1)/2, max_src, src, sport)
        else:
            s =   "    %*s:%-5s < " % (         max_src, src, sport)

#        hide_outside(timelines[i]);
        s += ''.join(timelines[i]);
        print "%s%s%s" % (col, s, color('e'));
        if i % 2 == 0:
            print ""

def loop_main():
    import sys
    args = sys.argv[:]  # save args
    for i in range(100):
        sys.argv = args[:] # restore
        main()


#main()
loop_main()
