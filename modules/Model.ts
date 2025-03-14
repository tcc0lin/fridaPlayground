export class CallbackModel {
  private _fucntion: string = "";
  private _data: ArrayBuffer | undefined;

  public setFunction(func: string): void {
    this._fucntion = func;
  }

  public setData(dt: ArrayBuffer): void {
    this._data = dt;
  }

  public getFunction(): string {
    return this._fucntion;
  }

  public getData(): ArrayBuffer | undefined {
    return this._data;
  }
}
