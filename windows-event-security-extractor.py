__author__ = "Fabian Voith"
__version__ = "1.0.0"
__email__ = "admin@fabian-voith.de"
 
import pandas as pd
import requests
import re
import warnings
from tqdm import tqdm
 
warnings.filterwarnings("ignore")
 
 
class pageManager:
    # static class, no instance, to organize event pages
    __pages = set()
     
    def enumeratePages():
        for page in pageManager.__pages:
            print(page)
             
    def countPages():
        return(len(pageManager.__pages))
 
    def addPage(page):
        pageManager.__pages.add(page)
         
    def purge():
        pageManager.__pages.clear()
         
    def saveToExcel(fileName):
        titles = []
        eventids = []
        flags = []
        links = []
        hasRecommendation = []
        recommendations = []
         
        colEVENTNAME = 'Event Name'
        colEVENTID = 'Event ID'
        colRESULT = 'Result'
        colHASRECOMMENDATION = 'Has Recommendation'
        colRECOMMENDATIONTEXT = 'Security Monitoring Recommendation'
        colURL = 'URL'
         
        for page in pageManager.__pages:
            titles.append(page.getTitle())
            eventids.append(page.getEventID())
            flags.append(page.getResultFlag())
            hasRecommendation.append(page.hasRecommendation())
            recommendations.append(page.getRecommendationText())
            links.append(page.getLink())
             
        table = {colEVENTNAME: titles, colEVENTID: eventids, colRESULT: flags, colHASRECOMMENDATION: hasRecommendation, colRECOMMENDATIONTEXT: recommendations, colURL: links}
 
        df = pd.DataFrame(table, columns = [colEVENTNAME, colEVENTID, colRESULT, colHASRECOMMENDATION, colRECOMMENDATIONTEXT, colURL])
        df[colEVENTID] = pd.to_numeric(df[colEVENTID])
        df.sort_values(by=[colEVENTID], inplace=True)
        df.to_excel(fileName, index=False)
         
  
 
class eventPage:
    # represents each individual page that we found
     
    def __init__(self, link, title, resultFlag, eventid, recommendationText, hasRecommendation):
        self.__link = link
        self.__title = title
        self.__resultFlag = resultFlag
        self.__eventid = eventid
        self.__recommendationText = recommendationText
        self.__hasRecommendation = hasRecommendation
         
    def getTitle(self):
        return(self.__title)
     
    def getLink(self):
        return(self.__link)
     
    def getResultFlag(self):
        return(self.__resultFlag)
     
    def getEventID(self):
        return(self.__eventid)
     
    def getRecommendationText(self):
        return(self.__recommendationText)
     
    def hasRecommendation(self):
        return(self.__hasRecommendation)
     
    def __repr__(self):
        return(f'Event "{self.getTitle()}" with ID {self.getEventID()} for result {self.getResultFlag()} is on {self.getLink()}')
     
 
class pageCreator:
    # static class to help us create proper pages that we later can save
     
    # prepare regular expressions for title...
    reUncleanTitle = re.compile(r'<h1.*>(.*)</h1>') # Title with all flags and event ID
    reCleanTitle = re.compile(r'.+: (.*)')          # Only title, without flags and ID
    reFlag = re.compile(r'\((.+)\):')        # Success, Failure, Both
    reEventID = re.compile(r'\d+')           # Numeric ID of the event
    # ... and for recommendation:
    # Even if an event does not have security recommendations, it still has the related section
    reRecommendationPart = re.compile(r'Security Monitoring Recommendations</h2>(.*)<!-- </content> -->', re.DOTALL)
    # If the part for recommendations contains something like "no recommendation" or
    # "no additional recommendations" we assume that no recommendation is given
    reHasNoRecommendationHint = re.compile(r'no\s\w*?\s?recommendation')
     
    def exists(path):
        # checks if website exists
        # since we are simply enumerating many event IDs, we will find many non-existant pages
        r = requests.head(path)
        return r.status_code == requests.codes.ok
     
    def create(link):
        # create page from scratch and do all necessary checks
        page = None
        if exists(link):
            html = requests.get(link, verify=False)
             
            # we need to fix the encoding, otherwise some characters will look very awakward
            html.encoding = html.apparent_encoding
            html = html.text
             
            title, flag, eventid = pageCreator.__parseTitle(html)
             
            recommendation, hasRecommendation = pageCreator.__parseRecommendation(html)
             
            page = eventPage(link, title, flag, eventid, recommendation, hasRecommendation)
             
        return(page)
     
    def __parseTitle(html):
        # parse title of web page to get some important information about event
         
        # with this, the title still contains (S, F) for Failure, Success, e.g. 4656(S, F): A handle to an object was requested.
        unclean_title = pageCreator.reUncleanTitle.search(html).group(1)
         
        # get result flag, for which event description is valid (S = Success, F = Failure, - = None)
        flag = pageCreator.reFlag.search(unclean_title).group(1)
         
        # get event id:
        eventid = pageCreator.reEventID.search(unclean_title).group(0)
 
        # remove result flag from title:
        clean_title = pageCreator.reCleanTitle.search(unclean_title).group(1)
         
        return(clean_title, flag, eventid)
     
    def __parseRecommendation(html):
         
        # Even if it says "no recommendation", we still assume that it DOES have a recommendation
        # if the part for recommendations is longer than or equal to 700 characters. In such cases "no recommendation"
        # usually only is meant for a small part in the recommendation area
        assumeRecommendationThreshold = 700
         
        # most events do have the recommendations part, but some very few like
        # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4671
        # do not have it
        try:
            recommendationPart = pageCreator.reRecommendationPart.search(html).group(1)
            hasRecommendation = True
        except:
            return('', False)
         
        if len(recommendationPart) < assumeRecommendationThreshold:
            # the recommendation part is quite short, let's check if we find a hint that no recommendation is given
            # if the text is longer than the threshold, we always assume that there is some recommendation
            noRecommendation = pageCreator.reHasNoRecommendationHint.search(recommendationPart)
             
            if noRecommendation:
                # if we did find  a string like "no recommendation" or "no additional recommendations" in a short
                # paragraph, we think that there is no recommendation
                hasRecommendation = False
                 
         
        # for the sake of completeness, we still return the recommendationText, 
        # even if we think that no recommendation was given
        return(recommendationPart, hasRecommendation)
         
 
# if we run the script using Jupyter notebook, our previous runs will
# have been stored by Jupyter, so we purge them first
pageManager.purge()
# "brute-force" relevant ID range 1000-6424
# we could also multi-thread this to make it faster
# we are using the tqdm library to show a nice progress bar
for eventid in tqdm(range(1000, 6425)):
    link = f'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{eventid}'
     
    page = pageCreator.create(link)
     
    if page != None:
        pageManager.addPage(page)
         
 
#pageManager.enumeratePages()
filename = 'windows-security-events.xlsx'
pageManager.saveToExcel(filename)
print(f'Saved {pageManager.countPages()} events to file {filename}.')
