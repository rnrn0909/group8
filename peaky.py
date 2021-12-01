from __future__ import print_function

import datetime
import hashlib
import librosa
import numpy as np
import pandas as pd


def checker(y):  # check input is valid or not and trim     # hash file gets too big when it uses over 20 seconds of file
    if stop > start and stop - start < 20:
        ny = y[start * sr:stop * sr]
    else:
        print('Please put right value!')
    return ny

def detect_peaks(sound, n_fft, hop_length):
    spec = np.abs(librosa.stft(sound, n_fft=n_fft, hop_length=hop_length))  # magnitudes
    freqs = librosa.fft_frequencies(n_fft=n_fft)  # frequency range
    tii = librosa.frames_to_time(spec[0], sr=sr, n_fft=n_fft,
                                 hop_length=hop_length)  # Converts frame counts to time (seconds).
    #   frames_to_time calculates: times[i] = frames[i] * hop_length / sr
    h1 = librosa.util.localmax(spec)  # get indices of array which have local max value in magnitudes // show it as true or false
    idx = np.where(h1 == True)
    co1 = idx[0]
    co2 = idx[1]
    cd = [] # get coordinates of indices
    for i in range(len(co1)):
        cd.append((co1[i], co2[i]))

    f_result = []
    t_result = []
    for i in range(len(cd)):
        f_result.append(freqs[cd[i][0]]) # find frequency values with indices
        t_result.append(tii[cd[i][1]]) # find time values with indices
    return f_result, t_result


MIN_HASH_TIME_DELTA = 0
MAX_HASH_TIME_DELTA = 200
FINGERPRINT_REDUCTION = 20  # Number of bits to throw away from the front of the SHA1 hash in the fingerprint calculation
DEFAULT_FAN_VALUE = 15  # Degree to which a fingerprint can be paired with its neighbors --
# Thresholds on how close or far fingerprints can be in time in order to be paired as a fingerprint.
def sav_hash_csv(h):
    df = pd.DataFrame(columns=['TIME', 'FREQ1', 'FREQ2', 'FINGERPRINT', 'START', 'STOP', 'TITLE'])
    pt = []
    pf1 = []
    pf2 = []
    ph = []
    stitle = []
    for i in range(len(h)):
        pt.append(h[i][0])
        pf1.append(h[i][1])
        pf2.append(h[i][2])
        ph.append(h[i][3])
        stitle.append(h[i][4])

    df['TIME'] = pt
    df['FREQ1'] = pf1
    df['FREQ2'] = pf2
    df['FINGERPRINT'] = ph
    df['START'] = start
    df['STOP'] = stop
    df['TITLE'] = stitle

    df.to_csv('%s_%s_to_%s_hash.csv' % (file[8:-4], start, stop))
    print("Peak hashes output to %s_%s_to_%s_hash.csv. \nProcess complete." % (file[8:-4], start, stop))
    return True

def attach_hash_csv(h):
    df = pd.DataFrame(columns=['TIME', 'FREQ1', 'FREQ2', 'FINGERPRINT', 'START', 'STOP', 'TITLE'])
    pt = []
    pf1 = []
    pf2 = []
    ph = []
    stitle = []
    for i in range(len(h)):
        pt.append(h[i][0])
        pf1.append(h[i][1])
        pf2.append(h[i][2])
        ph.append(h[i][3])
        stitle.append(h[i][4])

    df['TIME'] = pt
    df['FREQ1'] = pf1
    df['FREQ2'] = pf2
    df['FINGERPRINT'] = ph
    df['START'] = start
    df['STOP'] = stop
    df['TITLE'] = stitle

    with open('hash.csv', 'a') as f:
        df.to_csv(f, header = False)
    print("Peak hashes output to hash.csv. \nProcess complete.")
    return True

def generate_hash(f, t):
    # fmt = '%0.3f'
    combo = np.arange(2 * len(f), dtype=object).reshape((len(f), 2))
    for i in range(len(f)):
        c1 = t[i]  # time
        c2 = f[i]  # frequency
        combo[i][0] = c1
        combo[i][1] = c2
    harray = []
    for i in range(len(combo)):
        for j in range(1, DEFAULT_FAN_VALUE):
            if (i + j) < len(combo):
                f1 = combo[i][1]
                f2 = combo[i + j][1]
                t1 = float(combo[i][0])
                t2 = float(combo[i + j][0])
                t_delta = np.abs(t2 - t1)

                if t_delta >= MIN_HASH_TIME_DELTA and t_delta <= MAX_HASH_TIME_DELTA:
                    h = hashlib.sha1()
                    h.update(''.join('%s, %s, %s' % (f1, f2, t_delta)).encode('utf-8'))
                    HASH = h.hexdigest()[0:FINGERPRINT_REDUCTION]
                    HASH = int(HASH, 16)    # convert into integers
                    harray.append(t1)
                    harray.append(f1)
                    harray.append(f2)
                    harray.append(HASH)
                    harray.append(title)
    h_result = np.reshape(harray, (len(harray) // 5, 5))
    attach_hash_csv(h_result)
    sav_hash_csv(h_result)
    return h_result





def main():
    global file, start, stop, sr, title
    file = input('Enter the title: ')
    title = file
    file = './audio/' + file + '.wav'
    y, sr = librosa.load(file)
    duration = librosa.get_duration(y)  # Get file duration in seconds
    print("File duration(s): ", str(datetime.timedelta(seconds=duration)))  # Print duration to console
    print(' Please trim under 20 seconds!! '.center(20, '*'))     # due to performance problem(my laptop cannot handle with over 30 seconds of file)
    start = int(input('From where do you want to trim the song?(sec) '))
    stop = int(input('Where do you want to stop trimming the song?(sec) '))

    # Trim the audio file
    trim = checker(y)
    td = librosa.get_duration(trim)
    print(td, str(datetime.timedelta(seconds=td)))  # Print how long did user trimmed

    n_fft = 2048  # a default value of librosa.stft(), length of windowed signal after zeros
    hop_length = n_fft // 4  # a default value of librosa.stft(): win_length // 4

    F1, T1 = detect_peaks(trim, n_fft, hop_length)
    generate_hash(F1, T1)



if __name__ == "__main__":
    main()





# onset_env = librosa.onset.onset_strength(y=y, sr=sr, hop_length=512, aggregate=np.median) # where music notes start?
# frames = librosa.util.peak_pick(onset_env, 3, 3, 3, 5, 0.5, 10)  # values from example on documentation
# the frame indices of the peaks that are selected in onset envelope
# librosa.util.peak_pick(x, pre_max, post_max, pre_avg, post_avg, delta, wait)
# freq[i] = frames[i] * sr / window_length
# print('Peaks detected at: ', peak_times)

#        for t, lab in zip(times, annotations):
#            writer.writerow([(fmt % t), lab])
# what output.times_csv did (removed function)
# librosa.output.times_csv('./output/peak_times.csv', peak_times)

# The spectrogram is a discrete time-frequency representation. In librosa the frequency bins are along the first axis,
# and time along the second axis. The frequency bins depend on the number of FFTs chosen, and the time bins depend on the hop length.
# %0.3f : If you want to round it for printing purposes, you can use the proper format specifiers in printf(), i.e. printf("%0.3f\n", 0.666666666)

# reference: https://github.com/SKempin/audio-peak-detection/blob/master/peaks-detection.py
# https://librosa.org/doc/latest/generated/librosa.util.peak_pick.html?highlight=peak%20pick#librosa.util.peak_pick
# Librosa 0.6(old version) documentation
# http://man.hubwiz.com/docset/LibROSA.docset/Contents/Resources/Documents/generated/librosa.output.times_csv.html#librosa.output.times_csv
# https://stackoverflow.com/questions/53506970/how-can-i-get-the-specific-frequency-at-a-specific-timestamp-in-an-audio-file
# https://www.audiolabs-erlangen.de/resources/MIR/FMP/C2/C2_STFT-Conventions.html
# https://github.com/cloudedbats/cloudedbats_dsp/blob/master/dsp4bats/frequency_domain_utils.py
# https://notebook.community/cloudedbats/cloudedbats_dsp/notebooks/experimental/detect_multiple_harmonics
# https://github.com/miishke/PyDataNYC2015/blob/master/song_fingerprinting.ipynb
# https://willdrevo.com/fingerprinting-and-audio-recognition-with-python/
# https://github.com/itspoma/audio-fingerprint-identifying-python/blob/master/libs/fingerprint.py#L118
# http://conference.scipy.org/proceedings/scipy2015/pdfs/brian_mcfee.pdf
# https://github.com/miromasat/pitch-detection-librosa-python/blob/master/script_final.py