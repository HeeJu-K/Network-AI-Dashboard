import sys
from pathlib import Path
import faiss
from langchain.text_splitter import CharacterTextSplitter
from langchain.vectorstores import FAISS
from langchain.embeddings import OpenAIEmbeddings
import pickle
from langchain import OpenAI, LLMChain
from langchain.prompts import Prompt

#  pip install python-dotenv
from dotenv import load_dotenv
load_dotenv()

def train_and_save():
    trainingData = list(Path("data/facts/").glob("**/*.json"))

    if len(trainingData) < 1:
        print("The folder training/facts should be populated with at least one .txt or .md file.", file=sys.stderr)
        return
    
    data = []
    for training in trainingData:
        with open(training, encoding="utf8", errors='ignore') as f:
            print(f"Add {f.name} to dataset")
            data.append(f.read())
    
    textSplitter = CharacterTextSplitter(chunk_size=2000, separator="\n")
    
    docs = []
    for sets in data:
        docs.extend(textSplitter.split_text(sets))
    
    store = FAISS.from_texts(docs, OpenAIEmbeddings()) # try to elaborate on this
    faiss.write_index(store.index, "cache/training.index")
    store.index = None
    
    with open("cache/faiss.pkl", "wb") as f:
        pickle.dump(store, f)
    print('done!')
train_and_save()