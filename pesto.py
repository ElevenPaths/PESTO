import hashlib
import os.path
import sys
import pefile
import datetime
import sqlite3


class PESecurityCheck:
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # ASLR
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100  # DEP
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400  # SEH
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000  # CFG

    def __init__(self, pe):
        self.pe = pe

    def aslr(self):
        return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

    def dep(self):
        return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    def seh(self):
        return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NO_SEH)

    def cfg(self):
        return bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & self.IMAGE_DLLCHARACTERISTICS_GUARD_CF)


def get_arch_string(arch):
    if arch == 332:  # IMAGE_FILE_MACHINE_I386 = 0x014c
        return "I386"
    elif arch == 512:  # IMAGE_FILE_MACHINE_IA64 = 0x0200
        return "IA64"
    elif arch == 34404:  # IMAGE_FILE_MACHINE_AMD64 = 0x8664
        return "AMD64"
    else:
        return "Unknown architecture"


def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        barLength   - Optional  : character length of bar (Int)
    """

    format_str = "{0:." + str(decimals) + "f}"
    percents = format_str.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '#' * filled_length + '-' * (bar_length - filled_length)
    sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),
    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()


def print_statistics(dict_results):
    num_files = dict_results.get('num_files')

    percent_exe = (dict_results.get('num_exe') / float(dict_results.get('num_files'))) * 100
    percent_dll = (dict_results.get('num_dll') / float(dict_results.get('num_files'))) * 100

    percent_i386 = (dict_results.get('num_i386') / float(dict_results.get('num_files'))) * 100
    percent_amd64 = (dict_results.get('num_amd64') / float(dict_results.get('num_files'))) * 100
    percent_other = (dict_results.get('num_other_arch') / float(dict_results.get('num_files'))) * 100

    percent_aslr = (dict_results.get('num_aslr') / float(dict_results.get('num_files'))) * 100
    percent_dep = (dict_results.get('num_dep') / float(dict_results.get('num_files'))) * 100
    percent_seh = (dict_results.get('num_seh') / float(dict_results.get('num_files'))) * 100
    percent_cfg = (dict_results.get('num_cfg') / float(dict_results.get('num_files'))) * 100

    print "\n\nRESULTS:\n------------------------------------------------------------------------------"
    print "Total files analyzed : " + str(dict_results.get('num_files'))

    print "\nFile types:"

    print "\n\t\tEXE: %d/%d (%d%c)" % (dict_results.get('num_exe'), num_files, percent_exe, chr(37))
    print "\t\tDLL: %d/%d (%d%c)" % (dict_results.get('num_dll'), num_files, percent_dll, chr(37))

    print "\nArchitecture:"

    print "\n\t\tI386: %d/%d (%d%c)" % (dict_results.get('num_i386'), num_files, percent_i386, chr(37))
    print "\t\tAMD64: %d/%d (%d%c)" % (dict_results.get('num_amd64'), num_files, percent_amd64, chr(37))
    print "\t\tOther: %d/%d (%d%c)" % (dict_results.get('num_other_arch'), num_files, percent_other, chr(37))

    print "\nGuards:"

    print "\n\t\tASLR (disabled): %d/%d (%d%c)" % (dict_results.get('num_aslr'), num_files, percent_aslr, chr(37))
    print "\t\tDEP (disabled): %d/%d (%d%c)" % (dict_results.get('num_dep'), num_files, percent_dep, chr(37))
    print "\t\tSEH (enabled): %d/%d (%d%c)" % (dict_results.get('num_seh'), num_files, percent_seh, chr(37))
    print "\t\tCFG (disabled): %d/%d (%d%c)" % (dict_results.get('num_cfg'), num_files, percent_cfg, chr(37))

    print "\nRisk files:"

    if len(dict_results.get('risk_files')):
        for rf in dict_results.get('risk_files'):
            print "\t\t" + rf[0]
    else:
        print "\t\tNo risk files found."

    print "\n------------------------------------------------------------------------------"


def main(arg_path, arg_analysis_tag):

    continue_exec = True

    path = arg_path
    progress = 0
    num_files = 0

    log_filename = str(datetime.datetime.now()) + "__" + str(os.getpid()) + ".log"

    # Todo: Check if problems occurs when try to create a new BD

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        sql = "CREATE TABLE if not exists \"file_info\" (" \
              "`id_analysis`	TEXT NOT NULL," \
              "`root_folder`	TEXT NOT NULL," \
              "`file_path`	TEXT NOT NULL," \
              "`file_name`	TEXT NOT NULL," \
              "`file_extension`	TEXT NOT NULL," \
              "`architecture`	TEXT NOT NULL," \
              "`file_hash`	TEXT NOT NULL," \
              "`ASLR`	INTEGER," \
              "`DEP`	INTEGER," \
              "`SEH`	INTEGER," \
              "`CFG`	INTEGER" \
              ");"

        cursor.execute(sql)

    except Exception, e:

        continue_exec = False

        print "Error in database initialization. Try checking user permissions to script location directory." \
              "\n\tError info: " + repr(e)

        with open(log_filename, mode='a') as f_error:
            if conn is None:
                f_error.write(str(datetime.datetime.now()) + " -- Error in database creation/connection: "
                                                             "\n\tError info: " + repr(e))
            elif cursor is None:
                f_error.write(str(datetime.datetime.now()) + " -- Error in database cursor retrieving: "
                                                             "\n\tError info: " + repr(e))
                conn.close()

    if continue_exec:

        try:

            for folder, subs, files in os.walk(path):

                for filename in files:

                    filename = filename.lower()
                    if filename.endswith('.exe') or filename.endswith('.dll'):
                        num_files += 1

            print "\n%d .EXE y .DLL files found in %s\n" % (num_files, path)

        except Exception, e:
            with open(log_filename, mode='a') as f_error:
                f_error.write(str(datetime.datetime.now()) + " -- Error in files pre-count : "
                                                             "\n\tError info: " + repr(e))

        dict_results = {}

        for folder, subs, files in os.walk(path):

            for filename in files:

                filename = filename.lower()

                # TODO: Change by is_exe and is_dll functions
                if filename.endswith('.exe') or filename.endswith('.dll'):

                    file_path = os.path.join(folder, filename)

                    # Calculate file hash

                    f = None
                    file_hash = None
                    try:
                        f = open(file_path, 'rb')
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    except Exception, e:
                        with open(log_filename, mode='a') as f_error:
                            f_error.write(str(datetime.datetime.now()) + " -- Error calculating file hash: " +
                                          file_path + "\n\tError info: " + repr(e))

                    finally:
                        if f is not None:
                            f.close()

                    try:
                        if file_hash is not None:
                            sql = "select * from file_info where file_info.file_hash like \"" + file_hash + "\";"

                            cursor.execute(sql)

                            # This check avoid reanalyze duplicated files
                            if not cursor.fetchone():
                                pe = pefile.PE(file_path, True)

                                ps = PESecurityCheck(pe)

                                aslr = ps.aslr()
                                dep = ps.dep()
                                cfg = ps.cfg()
                                seh = ps.seh()
                                extension = filename[-4:]
                                architecture = get_arch_string(pe.FILE_HEADER.__getattribute__('Machine'))

                                pe.close()

                                sql = "INSERT INTO `file_info`(`id_analysis`,`root_folder`,`file_path`,`file_name`," \
                                      "`file_extension`,`architecture`,`file_hash`,`ASLR`,`DEP`,`SEH`,`CFG`) " \
                                      "VALUES ('%s',\"%s\",\"%s\",'%s','%s','%s',\"%s\",%d,%d,%d,%d);" % \
                                      (arg_analysis_tag, path, file_path, filename, extension, architecture,
                                       file_hash, aslr, dep, seh, cfg)

                                cursor.execute(sql)

                                conn.commit()

                    except (pefile.PEFormatError, Exception), e:
                        with open(log_filename, mode='a') as f_error:
                            f_error.write(str(datetime.datetime.now()) + " -- Error in file: " + file_path +
                                          "\n\tError info: " + repr(e))

                    progress += 1

                    print_progress(progress, num_files, prefix='Progress:', suffix='Complete', bar_length=50)

        # Get data results from database

        try:

            sql = "select * from file_info"
            cursor.execute(sql)
            dict_results.update({'num_files': len(cursor.fetchall())})

            sql = "select * from file_info where file_info.file_extension like '.exe'"
            cursor.execute(sql)
            dict_results.update({'num_exe': len(cursor.fetchall())})

            sql = "select * from file_info where file_info.file_extension like '.dll'"
            cursor.execute(sql)
            dict_results.update({'num_dll': len(cursor.fetchall())})

            sql = "select * from file_info where not file_info.ASLR"
            cursor.execute(sql)
            dict_results.update({'num_aslr': len(cursor.fetchall())})

            sql = "select * from file_info where not file_info.DEP"
            cursor.execute(sql)
            dict_results.update({'num_dep': len(cursor.fetchall())})

            sql = "select * from file_info where file_info.SEH"
            cursor.execute(sql)
            dict_results.update({'num_seh': len(cursor.fetchall())})

            sql = "select * from file_info where not file_info.CFG"
            cursor.execute(sql)
            dict_results.update({'num_cfg': len(cursor.fetchall())})

            sql = "select * from file_info where file_info.architecture like 'I386'"
            cursor.execute(sql)
            dict_results.update({'num_i386': len(cursor.fetchall())})

            sql = "select * from file_info where file_info.architecture like 'AMD64'"
            cursor.execute(sql)
            dict_results.update({'num_amd64': len(cursor.fetchall())})

            sql = "select * from file_info where file_info.architecture not like 'I386' " \
                  "and file_info.architecture not like 'AMD64'"
            cursor.execute(sql)
            dict_results.update({'num_other_arch': len(cursor.fetchall())})

            sql = "select file_path from file_info " \
                  "where not file_info.CFG and not file_info.ASLR and not file_info.DEP and file_info.SEH"
            cursor.execute(sql)
            dict_results.update({'risk_files': cursor.fetchall()})

            print_statistics(dict_results=dict_results)

        except Exception, e:
            with open(log_filename, mode='a') as f_error:
                f_error.write(str(datetime.datetime.now()) + " -- Failed to retrieve statistics from DB: " +
                              "\n\tError info: " + repr(e))
            print "Error: Failed to retrieve statistics from DB\n\tError info: " + repr(e)

        print "\nErrors exported to " + log_filename

        print "\nExport data? Press:"
        print "\t n -- Don't export"
        print "\t s -- Export to SQL script"
        print "\t c -- Export to CSV file"

        response = raw_input()

        while response != 'n' and response != 's' and response != 'c':
            print 'Please, enter a valid option [[n]/[s]/[c]]'
            response = raw_input()

        if response.lower() != 'n':
            try:
                sql = "select * from file_info"
                cursor.execute(sql)

                if response.lower() == 'c':
                    print "Exporting to CSV"

                    with open(arg_analysis_tag + '.csv', mode='a')as f:

                        header = '"id_analysis","root_folder","file_path","file_name",' \
                                 '"file_extension","architecture","file_hash","ASLR","DEP","SEH","CFG"'

                        f.write(header)

                        for row in cursor.fetchall():
                            w_row = '\n"%s","%s","%s",%s","%s","%s","%s","%d","%d","%d","%d"' % \
                                    (row[0], row[1], row[2], row[3], row[4], row[5],
                                     row[6], row[7], row[8], row[9], row[10])
                            f.write(w_row)

                if response.lower() == 's':
                    print "Exporting to SQL"
                    with open(arg_analysis_tag + '.sql', mode='a')as f:
                        sql = "BEGIN TRANSACTION;\n\n" \
                              "CREATE TABLE \"file_info\" (\n" \
                              "\t`id_analysis`	TEXT NOT NULL,\n" \
                              "\t`root_folder`	TEXT NOT NULL,\n" \
                              "\t`file_path`	TEXT NOT NULL,\n" \
                              "\t`file_name`	TEXT NOT NULL,\n" \
                              "\t`file_extension`	TEXT NOT NULL,\n" \
                              "\t`architecture`	TEXT NOT NULL,\n" \
                              "\t`file_hash`	TEXT NOT NULL,\n" \
                              "\t`ASLR`	INTEGER,\n" \
                              "\t`DEP`	INTEGER,\n" \
                              "\t`SEH`	INTEGER,\n" \
                              "\t`CFG`	INTEGER\n" \
                              ");\n"
                        f.write(sql)

                        for row in cursor.fetchall():
                            w_row = "INSERT INTO `file_info`(`id_analysis`,`root_folder`,`file_path`,`file_name`," \
                                    "`file_extension`,`architecture`,`file_hash`,`ASLR`,`DEP`,`SEH`,`CFG`) " \
                                    "VALUES ('%s',\"%s\",\"%s\",'%s','%s','%s',\"%s\",%d,%d,%d,%d);" % \
                                    (row[0], row[1], row[2], row[3], row[4], row[5],
                                     row[6], row[7], row[8], row[9], row[10])

                            f.write("\n" + w_row)

                        f.write("\n\nCOMMIT;")
            except Exception, e:
                with open(log_filename, mode='a') as f_error:
                    f_error.write(str(datetime.datetime.now()) + " -- Error in data export:" +
                                  "\n\tError info: " + repr(e))

        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()

        # TODO: Handle errors when try to remove DB.
        try:
            os.remove('database.db')
        except Exception, e:
            with open(log_filename, mode='a') as f_error:
                f_error.write(str(datetime.datetime.now()) + " -- Error. Unable to remove database:" +
                              "\n\tError info: " + repr(e))

if __name__ == '__main__':

    if len(sys.argv) < 3:
        print 'Usage: %s <file_path> <analysis_tag>' % sys.argv[0]
        sys.exit("Invalid number of arguments")
    else:
        main(arg_path=sys.argv[1], arg_analysis_tag=sys.argv[2])
