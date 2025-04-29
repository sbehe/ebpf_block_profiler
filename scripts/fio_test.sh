#!/bin/bash
fio --name=randread --ioengine=libaio --rw=randread --bs=4k --size=512M --numjobs=4 --runtime=30 --group_reporting