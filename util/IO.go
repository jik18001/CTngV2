package util

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

//This read function reads from a Json file as a byte array and returns it.
//This function will be called for all the reading from json functions

func ReadByte(filename string) ([]byte, error) {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil {
		return nil, err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	return byteValue, nil
}

//Writes arbitrary data as a JSON File.
// If the file does not exist, it will be created.
func WriteData(filename string, data interface{}) error {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil && strings.Contains(err.Error(), "no such file or directory") {
		jsonFile, err = os.Create(filename)
	}
	if err != nil {
		return err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	//write to the corresponding file
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func CreateFile(path string) {
	// check if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			return
		}
		defer file.Close()
	}
}

func CreateDir(path string) {
	// check if directory exists
	var _, err = os.Stat(path)
	// create directory if not exists
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		if errDir != nil {
			return
		}
	}
}

func DeleteFilesAndDirectories(path string) error {
	// Open the directory specified by the path
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	// Read all the contents of the directory
	fileInfos, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	// Loop through all the files and directories in the directory
	for _, fileInfo := range fileInfos {
		// Create the full path to the file or directory
		fullPath := path + "/" + fileInfo.Name()

		// If the file or directory is a directory, recursively delete it
		if fileInfo.IsDir() {
			if err := DeleteFilesAndDirectories(fullPath); err != nil {
				return err
			}
		} else {
			// Otherwise, delete the file
			if err := os.Remove(fullPath); err != nil {
				return err
			}
		}
	}

	// Finally, delete the directory itself
	if err := os.Remove(path); err != nil {
		return err
	}

	return nil
}

func LoadConfiguration(config interface{}, file string) { //takes in the struct that it is updating and the file it is updating with
	// Let's first read the file
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}
	// Now let's unmarshall the data into `payload`
	err = json.Unmarshal(content, config)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}
}
