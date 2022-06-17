import {lstatSync, readFileSync} from 'fs';
import {getType} from 'mime';
import {basename, posix} from 'path';
import axios, {AxiosInstance} from 'axios';
import * as FormData from 'form-data';
import * as core from '@actions/core';

interface UploadData {
  id: string;
  type: string;
  url: string;
}

export interface Asset {
  name: string;
  mime: string;
  size: number;
  file: Buffer;
}

export class VirusTotal {
  private instance: AxiosInstance;
  // private largeURL = '';
  private apiKey = '';

  constructor(apiKey: string | undefined) {
    this.apiKey = apiKey ?? '';
    this.instance = axios.create({
      baseURL: '',
      headers: {
        'x-apikey': apiKey ?? ''
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });
  }

  private async getURL(apiKey: string | undefined): Promise<string> {
    const instance: AxiosInstance = axios.create({
      baseURL: '',
      headers: {
        Accept: 'application/json',
        'x-apikey': apiKey ?? ''
      }
    });

    return await instance.get('https://www.virustotal.com/api/v3/files/upload_url').then(res => {
      return res.data.data;
    });
  }

  // async getLargeFileURL(apiKey: string | undefined) {
  //   this.largeURL = await this.getURL(apiKey);
  // }

  async files(filename: string): Promise<UploadData> {
    const {name, mime, size, file} = asset(filename);
    const fd = new FormData();
    fd.append('file', file, {
      filename: name,
      contentType: mime,
      knownLength: size
    });

    return this.instance
      .post(await this.getURL(this.apiKey), fd.getBuffer(), {
        headers: fd.getHeaders()
      })
      .then(upload => {
        const data = upload.data.data as UploadData;
        data.url = `https://www.virustotal.com/gui/file-analysis/${data.id}/detection`;
        return data;
      })
      .catch(error => {
        throw new Error(`Cannot send ${name} to VirusTotal: ${error}`);
      });
  }

  monitorItems(filename: string, path?: string): Promise<UploadData> {
    const {name, mime, size, file} = asset(filename);
    const fd = new FormData();
    fd.append('file', file, {
      filename: name,
      contentType: mime,
      knownLength: size
    });

    const itemPath: string = posix.join(path ? path : '/', name);
    core.debug(`monitorItems path: ${itemPath}`);
    fd.append('path', itemPath);

    return this.instance
      .post('https://www.virustotal.com/api/v3/monitor/items', fd.getBuffer(), {
        headers: fd.getHeaders()
      })
      .then(upload => {
        const data = upload.data.data as UploadData;
        data.url = `https://www.virustotal.com/monitor/analyses/item:${data.id}`;
        return data;
      })
      .catch(error => {
        throw new Error(`Cannot send ${name} to VirusTotal Monitor at ${itemPath}: ${error}`);
      });
  }
}

export const asset = (path: string): Asset => {
  return {
    name: basename(path),
    mime: mimeOrDefault(path),
    size: lstatSync(path).size,
    file: readFileSync(path)
  };
};

export const mimeOrDefault = (path: string): string => {
  return getType(path) || 'application/octet-stream';
};
