from os import path
import youtube_dl
from youtube_dl import YoutubeDL
import logging
import subprocess
from pathlib import Path


ydl = YoutubeDL({
    'format':'bestaudio',
    'max_filesize':10500000,
    'restrictfilenames':True,
    'forcefilenames':True,
    'outtmpl':str('%(title)s.mp3'),
    'ignoreerrors':True,
    'postprocessors':[{
        'key':'FFmpegExtractAudio',
        'preferredcodec':'mp3',
        'preferredquality':'192'
    }]
})


def ytscrapper():
    while True:
        try:
            print ('Audio Downloader'.center(40, '_'))
            video_info = ydl.extract_info("ytsearch5:no copyright music")
            options = {
                 'keepvideo':False,
#        'max_filesize':25000000
            }
            filename = ydl.prepare_filename(video_info)
#    filename = video_info['title']
#    src = filename+".mp3"
#    dst = filename+".wav"
#    print filename
#    sound = AudioSegment.from_mp3(src)
#    sound.export(dst, format = "wav")
#    print video_info['title']
            subprocess.call(['ffmpeg', '-i', filename, filename+'.wav'])
        except Exception:
             logging.exception("Error occurred while downloading video")
    print ("Download Completed!")


ytscrapper()

for filename in Path(".").glob("*.part"):
    filename.unlink
