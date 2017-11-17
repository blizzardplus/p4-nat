from Crypto import Random
import math
import matplotlib.pyplot as plt
import numpy

#global rndDesc

masks = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x40, 0x80]


class PRNGExp:
    def maskTagCand(self, tagCand):
        mask = 2**(self.maskLength) - 1
        tagbytes = bytearray(tagCand)
        tagbytes[len(tagbytes)-1] &= mask
        return str(tagbytes)

    def getNextByteSeq(self):
        tagCand = self.rndDesc.read(self.tagByteLen)
        if (self.maskNeeded):
            tagCand = self.maskTagCand(tagCand)
        self.totalTags += 1
        return tagCand

    def addTagToDict(self, tagCand):
        if tagCand in self.tagDic:
            return False
        else:
            self.tagDic[tagCand] = 1
            self.totalSuccTags += 1
            return True

    def findNextTag(self):
        cond = self.addTagToDict(self.getNextByteSeq())
        while not cond:
            cond = self.addTagToDict(self.getNextByteSeq())

    # TagLength is in bits
    def __init__(self, tagLength):
        self.tagLength  = tagLength
        self.tagByteLen = int(math.ceil(float(tagLength) / float(8)))
        self.maskLength = tagLength % 8
        self.maskNeeded = False if self.maskLength == 0 else False
        self.rndDesc = Random.new()
        self.totalTags = 0
        self.totalSuccTags = 0 # Total number of tags successfully added
        self.tagDic = {}


FlowCount = 1000000
indvTestRepScale = 10000
testRepScale =  20
testRep = 2

def testFunction(tagLength, localFlowCount):
    prng = PRNGExp(tagLength)
    prng2Array = [None] * localFlowCount #Maps flow count to total tags generated
    for i in range(localFlowCount):
        prng.findNextTag()
        prng2Array[i] = prng.totalTags
        if (i % indvTestRepScale) == 0:
            print("%s : %s" % (i , prng2Array[i]))
    return prng2Array

def testExecAggr(tagLength):
    localFlowCount = min(FlowCount, int(0.9 * float(2**tagLength)))
    print ("Flowcount considered %s:" % localFlowCount)
    sumArray = [0] * localFlowCount
    for i in range(testRep):
        print("Iteration %s" % i)
        testArray = testFunction(tagLength, localFlowCount)
        sumArray = [x + y for x, y in zip(sumArray, testArray)]
    meanArray = [int(float(x)/float(testRep)) for x in sumArray]
    for t in range(len(meanArray)):
        if (t % indvTestRepScale) == 0:
            print("%s : %s" % (t , meanArray[t]))
    plt.plot(range(len(meanArray)), meanArray , c=numpy.random.rand(3,))

if __name__ == '__main__':
    plt.figure(1)
    for i in range (16, 30, 2):
        print("Executing for %s"% i)
        testExecAggr(i)
    plt.ylabel('some numbers')
    plt.show()
