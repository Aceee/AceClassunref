#!/usr/bin/python3

import os
import re
import sys

def verified_app_path(path):
    if path.endswith('.app'):
        #  appname = path.split('/')[-1].split('.')[0]
        appname = os.path.splitext(path)[0].split('/')[-1]
        # XesApp.app后面拼接XesApp
        path = os.path.join(path, appname)
    if not os.path.isfile(path):
        return None
    if not os.popen('file -b ' + path).read().startswith('Mach-O'):
        return None
    return path


def pointers_from_binary(line, binary_file_arch):
    if len(line) < 16:
        return None
    line = line[16:].strip().split(' ')
    pointers = set()

    if len(line) >= 2:
        pointers.add(line[1] + line[0])
    if len(line) >= 4:
        pointers.add(line[3] + line[2])
    return pointers
    # return None


def class_ref_pointers(path, binary_file_arch):
    print('获取引用类')
    ref_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classrefs %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        ref_pointers = ref_pointers.union(pointers)
    if len(ref_pointers) == 0:
        exit('引用类为空')
    return ref_pointers


def class_list_pointers(path, binary_file_arch):
    print('获取所有类')
    list_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classlist %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        # 过滤重复项添加到set集合中
        list_pointers = list_pointers.union(pointers)
    if len(list_pointers) == 0:
        exit('所有类为空')
    return list_pointers


def class_symbols(path):
    print('获取类符号')
    symbols = {}
    re_class_name = re.compile('(\w{16}) .* _OBJC_CLASS_\$_(.+)')
    lines = os.popen('nm -nm %s' % path).readlines()
    for line in lines:
        result = re_class_name.findall(line)
        if result:
            (address, symbol) = result[0]
            symbols[address] = symbol
    if len(symbols) == 0:
        exit('Error:class symbols null')
    return symbols

def filter_super_class(unref_symbols):
    # 过滤父类
    re_subclass_name = re.compile("\w{16} 0x\w{9} _OBJC_CLASS_\$_(.+)")
    re_superclass_name = re.compile("\s*superclass 0x\w{9} _OBJC_CLASS_\$_(.+)")
    #subclass example: 0000000102bd8070 0x103113f68 _OBJC_CLASS_$_XesStatusDetailItemView
    #superclass example: superclass 0x10313bb80 _OBJC_CLASS_$_XesBaseControlView
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()
    subclass_name = ""
    superclass_name = ""
    for line in lines:
        subclass_match_result = re_subclass_name.findall(line)
        if subclass_match_result:
            subclass_name = subclass_match_result[0]
        superclass_match_result = re_superclass_name.findall(line)
        if superclass_match_result:
            superclass_name = superclass_match_result[0]

        if len(subclass_name) > 0 and len(superclass_name) > 0:
            if superclass_name in unref_symbols and subclass_name not in unref_symbols:
                unref_symbols.remove(superclass_name)
            superclass_name = ""
            subclass_name = ""
    return unref_symbols

def class_unref_symbols(path):
    #binary_file_arch: distinguish Big-Endian and Little-Endian
    #file -b 获取mach-o中的设备架构
    binary_file_arch = os.popen('file -b ' + path).read().split(' ')[-1].strip()
    # 差值
    unref_pointers = class_list_pointers(path, binary_file_arch) - class_ref_pointers(path, binary_file_arch)
    if len(unref_pointers) == 0:
        exit('Finish:没有未使用的文件')

    symbols = class_symbols(path)
    unref_symbols = set()
    for unref_pointer in unref_pointers:
        if unref_pointer in symbols:
            unref_symbol = symbols[unref_pointer]
            unref_symbols.add(unref_symbol)
    if len(unref_symbols) == 0:
        exit('Finish:三方库私有化处理后没有未使用的类')
    return filter_super_class(unref_symbols)


def phoneAndPadRefListFilter (path):
    if not path:
        sys.exit('无效的app路径')


    unref_symbols = class_unref_symbols(path)
    fileList = []
    for unref_symbol in unref_symbols:
        # 判断是否为X开头的文件
        if unref_symbol.startswith('X'):
            # print('未使用文件: ' + unref_symbol)
            fileList.append(unref_symbol)
    return fileList


if __name__ == '__main__':
    path = input('输入以.app为结尾的iPhone文件\n').strip()
    path = verified_app_path(path)
    iPhoneList = phoneAndPadRefListFilter(path)
    path = input('输入以.app为结尾的iPad端文件\n').strip()
    path = verified_app_path(path)
    iPadList = phoneAndPadRefListFilter(path)

    results = [k for k in iPhoneList if k in iPadList]
    script_path = sys.path[0].strip()

    f = open(script_path + '/result.txt', 'w')
    f.write('未使用文件个数: %d\n' % len(results))
    iphoneAndPadFilter = set()
    for result in results:
        if not result.startswith('XOL'):
            print('手机和pad都未使用过滤掉XOL的文件：' + result)
            f.write(result + "\n")
            iphoneAndPadFilter.add(result)
    f.close()
    print('未使用文件个数: %d' % len(iphoneAndPadFilter))
    print('完成，X开头并且手机和pad都未使用过滤掉XOL的文件的无用文件已写到result.txt中')

    iphoneFileFilter = set()
    for iphoneFile in iPhoneList:
        if not iphoneFile.startswith('XOL'):
            print('手机端X开头并且过滤掉XOL的文件的无用文件:' + iphoneFile)
            iphoneFileFilter.add(iphoneFile)
    print('手机端X开头并且过滤掉XOL的文件的无用文件个数%d' % len(iphoneFileFilter))

    iPadNotFilter = set()
    iPadNotFilter = iphoneFileFilter - iphoneAndPadFilter
    for file in iPadNotFilter:
        print('手机端没用pad端用了或者pad上都没有这个文件:' + file)
    print('手机端没用pad端用了或者pad上都没有这个文件，个数%d' % len(iPadNotFilter))