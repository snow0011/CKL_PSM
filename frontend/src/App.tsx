import React, {ChangeEvent, Component, FormEvent} from 'react';
import {Button, Card, Col, Descriptions, Input, Progress, Row, Statistic, Space} from "antd";
import {LockOutlined, SecurityScanOutlined, EyeInvisibleOutlined, EyeTwoTone} from "@ant-design/icons";
import {Md5} from "ts-md5/dist/md5";

/*
Interface of password query result.
guess number: the guess number of the password which is estimated by monte carlo method. 
segments: password is segmented into several chunks.
chunks: segments and flag marked as dangerous chunks.
prob: guessing probability of the password.
*/
interface Result {
    guess_number: number,
    segments: string[],
    chunks: [string, boolean][],
    prob: number,
}

/*
The rank list and dangerous chunks for our PCFG password meter.
probs: the list of minus log probability of sample passwords.
positions: the guess number of corresponding passwords.
blocklist: dangerous chunks which imply a password with the chunks is easy to guess. 
*/
interface RankList{
    positions:number[],
    probs: number[],
    blocklist: string[],
}

/*
List of segments of PCFG model. We build a map from segment to its probability.
For example, the corresponding probability of the segment "123456" is "0.0015".
*/
interface PCFGSegment{
    [index: string]: number
}

/*
PCFG terminals which contain several PCFG segments.
For our PCFG model, the terminal includes "L", "U", "D", "S", "DM", "TM" and "FM".
*/
interface PCFGTerminal{
    [index: string]: PCFGSegment
}

/*
JSON type of our PCFG model which is the output of PCFG training.
grammar: The structures of PCFG model.
lower: Lower case terminals and their corresponding probability.
upper: Upper case terminals and their corresponding probability.
digits: Digital terminals and their corresponding probability.
special: Special case terminals and their corresponding probability.
*/
interface PCFGModel {
    "grammar": PCFGSegment, 
    "lower": PCFGTerminal, 
    "upper": PCFGTerminal, 
    "double_m": PCFGTerminal, 
    "triple_m": PCFGTerminal, 
    "four_m": PCFGTerminal, 
    "digits": PCFGTerminal, 
    "special": PCFGTerminal
}

/*
We use CharacterType to descripe the type of a password segments. 
For example, segment "p@ssw0rd" is {upper: 0, lower: 1, digit: 1, special: 1} 
and final terminal is TM8.
*/
class CharacterType {
    /* 
    The attributes mark the segment whether has upper case 
    letter, lower case letter, digital character or sepcial character 
    */
    upper:number = 0;
    lower:number = 0;
    digit:number = 0;
    special:number = 0;

    /*
    Merge two segments and corresponding types.
    For example, the segment "p@ss" with {upper: 0, lower: 1, digit: 0, special: 1} 
    join the segment "w0rd" with {upper: 0, lower: 1, digit: 1, special: 0} is
    {upper: 0, lower: 1, digit: 1, special: 1}.
    */
    join(character:CharacterType) {
        this.upper = character.upper | this.upper;
        this.lower = character.lower | this.lower;
        this.digit = character.digit | this.digit;
        this.special = character.special | this.special;
    }

    /*
    Return the terminal symbol of this segment.
    */
    terminal():string{
        let total = this.lower + this.upper + this.digit + this.special;
        if(total === 1){
            if(this.upper===1){
                return "U";
            }
            if(this.lower===1){
                return "L";
            }
            if(this.digit===1){
                return "D";
            }
            if(this.special===1){
                return "S";
            }
        }
        if(total===2){
            return "DM";
        }
        if(total===3){
            return "TM";
        }
        if(total===4){
            return "FM";
        }
        return "None";
    }

    /*
    Return a character type by giving a Terminal symbol.
    */
    static get_type(luds: string):CharacterType{
        let res:  CharacterType = new CharacterType();
        switch(luds){
            case "L":
                res.lower = 1;
                break;
            case "D":
                res.digit = 1;
                break;
            case "U":
                res.upper = 1;
                break;
            case "S":
                res.special = 1;
                break;
        }
        return res;
    }
}

/* PCFG model for query */
let pcfg_model: PCFGModel;
/* Mark PCFG model ready or not */
let model_ready: boolean = false;
/* Monte carlo probability list */
let rank_list: RankList;
/* Monte carlo probability list load or not */
let rank_ready:boolean = false;
/* block list which implys dangerous chunks in password */
let block_chunks: Set<string>;

/* Backend API for communication */
const api = (async function () {
    const conf = await import("./ip.json");
    return `http://${conf.default}:3001/`;
})();

async function load_ranks() {
    let start = new Date().getTime();
    /* rank API */
    const real_api = (await api)+"pcfgrank";
    const response: Response = await fetch(real_api, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/gzip',
            'Access-Control-Allow-Origin': '*',
        }
    });
    /* load monte carlo list, we also use gzip to compress the list */
    rank_list = await response.json();
    /* add last position to avoid index out of range */
    rank_list.positions.push(rank_list.positions[rank_list.positions.length-1]);
    /* A block list set to query easily */
    block_chunks = new Set(rank_list.blocklist);
    rank_ready = true;
    let end = new Date().getTime();
    const elapse = end - start;
    console.log("Monte carlo rank list loading time: " + elapse)
}

async function load_model() {
    let start = new Date().getTime();
    /* rank API */
    const real_api = (await api)+"pcfgmodel";
    const response: Response = await fetch(real_api, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/gzip',
            'Access-Control-Allow-Origin': '*',
        }
    });
    /* load model and set global variables. Here, we use gzip to compress the model */
    pcfg_model = await response.json();
    /* all query call should work now */
    model_ready = true;
    let end = new Date().getTime();
    const elapse = end - start;
    console.log("Model loading time: " + elapse)
}

function isUpper(ch: number): boolean{
    return ch >= "A".charCodeAt(0) && ch <= "Z".charCodeAt(0);
}

function isLower(ch: number): boolean{
    return ch >= "a".charCodeAt(0) && ch <= "z".charCodeAt(0);
}

function isDigit(ch: number): boolean{
    return ch >= "0".charCodeAt(0) && ch <= "9".charCodeAt(0);
}

/*
Return hidden text of given text. Hidden text is string which is consist of "*".
*/
function hidden_text(password:string){
    let ans = "";
    for(let i = 0; i < password.length; i++){
        ans += "*";
    }
    return ans;
}

/* 
Binary seach for rank positions seaching. 
Return index of target value.
*/
function binarySearch<T>(arr: T[], target: T): number {
    let l = 0, r = arr.length - 1;
    while(l <= r) {
        let mid = Math.floor(l + (r - l) / 2);
        if (arr[mid] >= target) {
            r = mid - 1;
        } else {
            l = mid + 1;
        }
    }
    return l;
}

/*
The segments in pcfg model are encoded.
We need to encode the segments which are used to query.
*/
function hash_funtion(segment:string){
    /* In order to reduce size of information of communication, we only use [8,-8] in md5 encoding. */
    const length = 12;
    return Md5.hashStr(segment).substr(length,2*(16-length));
    // return segment;
}

/*
Return the character type list of the giving password.
For example, giving password "p@ssw0rd", it should return "LSLLLDLL".
*/
function raw_luds(password: string): string{
    let res: string = "";
    let cur_tag:string = " ";
    for(let i = 0; i < password.length; i++){
        const ch = password.charCodeAt(i);
        if(isUpper(ch)){
            cur_tag = "U";
        }
        else if(isLower(ch)){
            cur_tag = "L";
        }
        else if(isDigit(ch)){
            cur_tag = "D";
        }
        else{
            cur_tag = "S";
        }
        res = res + cur_tag;
    }
    return res;
}

/*
For a password, we calculate all terminals which may be used. 
i.e. we check all subtrings of the password and get its terminals.
For example, the state table of password "p@ss" is
[0,0]: D1
[0,1]: DM2
[0,2]: DM3
[0,3]: DM4
......
*/
function get_state_table(structure: string):CharacterType[][]{
    let dp: CharacterType[][] = new Array(structure.length);
    for(let i = 0; i < structure.length; i++){
        dp[i] = new Array(structure.length+1);
        for(let j = 0; j < structure.length; j++){
            dp[i][j] =  new CharacterType();
        }
    }
    for(let i = 0; i < structure.length; i++){
        dp[i][i] = CharacterType.get_type(structure.charAt(i));
    }
    for(let i = 1; i < structure.length; i++){
        for(let j = 0; j < structure.length-i; j++){
            dp[j][j+i].join(dp[j][j+i-1]);
            dp[j][j+i].join(CharacterType.get_type(structure.charAt(j+i)));
        }
    }
    return dp;
}

/*
Recover the password structure from string.
For example, giving structure "D2L10S3", it will return [("D",2),("L",10),("S",3)]
*/
function grammar_to_array(grammar:string):[string, number][] {
    let segment:string = "";
    let result: [string, number][] = [];
    let see_number:boolean= false;
    let number_value:string = "";
    for(let i = 0; i < grammar.length; i++){
        let ch = grammar.charAt(i);
        /* handle the digital part */
        if(isDigit(grammar.charCodeAt(i))){
            see_number = true;
            number_value+=ch;
            continue;
        }
        /* handle the letter part */
        if(!isDigit(grammar.charCodeAt(i)) && see_number){
            let value = parseInt(number_value);
            result.push([segment, value]);
            /* reset the string and flag */
            segment ="";
            number_value = "";
            see_number = false;
        }
        segment += ch;
    }
    let value = parseInt(number_value);
    result.push([segment, value]);
    return result;
}

/*
Check a structure whther match a password. 
For example, giving password "p@ssw0rd" and structure "DM2L3DM3"
will return true. And structure "L3D2S1L5" will return false.
*/
function valid_grammar(structure:string, grammar: [string, number][], state_table:CharacterType[][]):boolean{
    let length = 0;
    /* get the expect length of the password */
    for(let i = 0; i < grammar.length; i++){
        length += grammar[i][1];
    }
    /* Most of structures have diffrent length, so we filter them. */
    if(structure.length !== length){
        return false;
    }
    /* match every terminal until all terminals are satisfied */
    let index =0;
    for(let i = 0; i < grammar.length; i++){
        let tag_len = grammar[i][1];
        let tag:string = grammar[i][0];
        let ct = state_table[index][index+tag_len-1];
        if(ct.terminal() !== tag){
            return false;
        }
        index += tag_len;
    }
    return true;
}

/*
For giving segment, return the probability of such segment in our PCFG model.
*/
function get_prob_of(segment:string, terminal:[string, number]) {
    let term:string = terminal[0] + terminal[1];
    let terminal_dict:PCFGTerminal = {};
    switch(terminal[0]){
        case "L":
            terminal_dict = pcfg_model.lower;
            break;
        case "U":
            terminal_dict = pcfg_model.upper;
            break;
        case "D":
            terminal_dict = pcfg_model.digits;
            break;
        case "S":
            terminal_dict = pcfg_model.special;
            break;
        case "DM":
            terminal_dict = pcfg_model.double_m;
            break;
        case "TM":
            terminal_dict = pcfg_model.triple_m;
            break;
        case "FM":
            terminal_dict = pcfg_model.four_m;
            break;
    }
    /* we used md5 to encode our model. for query, we should also encode the segment. */
    segment = hash_funtion(segment);
    return terminal_dict[term][segment];
}

/*
For a password, calculate the probability of given structure.
*/
function calculate_prob(password:string, grammar: [string, number][]):[number, string[]]{
    let res:string[] = [];
    let index:number = 0;
    let prob:number = 0.0;
    for(let i = 0; i < grammar.length; i++){
        let len:number = grammar[i][1];
        let segment:string = password.substring(index, index+len);
        index += len;
        res.push(segment);
        /* minus log probablity */
        prob += get_prob_of(segment, grammar[i]);
    }
    return [prob,res];
}

/*
Check the password chunks whether are dangerous chunks.
*/
function check_chunks(chunks:string[], block_set:Set<string>):[string,boolean][]{
    let result:[string,boolean][] = [];
    for(let chunk of chunks){
        const hash_chunk = Md5.hashStr(chunk)
        result.push([chunk, block_chunks.has(hash_chunk)] );
    }
    return result;
}

/*
Local query of password strength.
*/
function local_query(password: string): [Result, number] {
    let start = new Date().getTime();
    /* model is loading, cancel querying */
    if(!model_ready || !rank_ready || password.length < 1){
        return [{"guess_number": -1, segments: [],chunks: [], prob:0.0}, 1];
    }
    /* compute the structure of giving password */
    const structure = raw_luds(password);
    /* Terminal table of password substrings */
    const password_dp= get_state_table(structure);
    /* PCFG structures */
    const grammar_dict:any = pcfg_model.grammar;
    const grammar_map:Map<string, number> = new Map(Object.entries(grammar_dict));
    /* find structures which match the password */
    let candicate_grammar:[string,number,[string, number][]][] = [];
    let data:[string, number][][] = [];
    grammar_map.forEach((value:number,key:string) => {
        const grammar:[string, number][] = grammar_to_array(key);
        data.push(grammar);
        if(valid_grammar(structure, grammar, password_dp)){
            candicate_grammar.push([key, value, grammar]);
        }
    });
    /* calculate password probability and select max one as final result */
    let result:[string,number,string[]][] = [];
    let final_result:[string,number,string[]] = ["",100,[]];
    candicate_grammar.forEach((value) => {
        let ret = calculate_prob(password, value[2]);
        let prob = ret[0];
        let segments = ret[1];
        prob += value[1];
        result.push([value[0],prob,segments]);
        if(prob < final_result[1]){
            final_result = [value[0],prob,segments];
        }
    });
    // console.log(result);
    // console.log(final_result);
    let prob = isNaN(final_result[1])?0:Math.pow(2,-final_result[1]);
    /* default guess number is max guess number */
    let guess_number:number = rank_list.positions[rank_list.positions.length-1];
    if(!isNaN(final_result[1])){
        let bisect = binarySearch(rank_list.probs, final_result[1]);
        guess_number = rank_list.positions[bisect];
    }
    const res:Result = {
        "guess_number": guess_number, 
        "segments": final_result[2],
        "chunks": check_chunks(final_result[2], block_chunks), 
        "prob":prob
    };
    let end = new Date().getTime();
    const elapse = end - start;
    return [res, elapse];
}

interface HomeState {
    password: string,
    bak_pwd: string,
    time_elapse: number,
    disable_btn: boolean,
    guess_number: number,
    chunks: [string, boolean][],
    prob: number,
    plain_text: boolean
}


export default class Home extends Component<{}, HomeState> {
    readonly state: HomeState = {
        chunks: [],
        prob: 1.0,
        guess_number: 0,
        time_elapse: 0,
        password: "",
        bak_pwd: "",
        disable_btn: false,
        plain_text: false
    }

    handleSubmit(e: FormEvent) {
        e.preventDefault();
        const password = this.state.password;
        let value = local_query(password);
        const [res, elapse] = value;
        this.setState({
            time_elapse:  elapse, 
            guess_number: res.guess_number,
            chunks: res.chunks,
            prob: res.prob,
            bak_pwd: password,
        });
    }

    handlePasswordChange(e: ChangeEvent<HTMLInputElement>) {
        this.setState({
            "password": e.target.value,
        });
    }

    handleVisiableChange(e: FormEvent){
        this.setState({
            "plain_text": !this.state.plain_text
        })
    }

    render() {
        let score, color, progress;
        let gn = this.state.guess_number;
        if (gn <= 0) {
            score = '';
            color = '';
            progress = 0
        } else if (gn < 10 ** 6) {
            score = "Weak"
            color = '#cf1322'
            progress = 33;
        } else if (gn < 10 ** 14) {
            score = 'Medium'
            color = '#F1C40F';
            progress = 66;
        } else {
            score = 'Strong'
            color = '#3f8600';
            progress = 100;
        }

        let show_gn;
        if (gn > 1000) {
            const p4gn = Math.floor(Math.log(this.state.guess_number) / Math.LN10);
            const n4gn = Math.round(this.state.guess_number * Math.pow(10, -p4gn) * 100) / 100;
            show_gn = `${n4gn}e${p4gn}`;
        } else {
            show_gn = `${Math.floor(gn)}`;
        }
        const chunks = this.state.chunks;
        const prob = this.state.prob;
        let show_prob;
        if (prob < 0.001) {
            const p4pb = Math.floor(Math.log(this.state.prob) / Math.LN10);
            const n4pb = Math.round(this.state.prob * Math.pow(10, -p4pb) * 100) / 100;
            show_prob = `${n4pb}e${p4pb}`;
        } else if (prob < 1) {
            show_prob = `${prob.toFixed(4)}`;
        } else {
            show_prob = "1";
        }
        const dangerous_chunks: Set<string> = new Set();
        const cards = (chunks.length > 0) ? <Card key={"card"}>
            {chunks.map(((value, index, array) => {
                const width = `${(1 / array.length * 100).toFixed(1)}%`;
                const chunk: string = value[0];
                const dangerous: boolean = value[1];
                const color: string = (dangerous) ? "#cf1322" : "#3f8600";
                if (dangerous) dangerous_chunks.add(this.state.plain_text?chunk:hidden_text(chunk));
                return <Card.Grid
                    key={index}
                    style={{
                        width: width,
                        textAlign: 'center',
                        paddingTop: '4px',
                        paddingBottom: '4px'
                    }}
                    hoverable={dangerous}
                >
                    <Statistic
                        value={this.state.plain_text?chunk:hidden_text(chunk)}
                        precision={0}
                        valueStyle={{color: color}}
                        suffix={""}
                        formatter={(v) => v}
                    />
                </Card.Grid>;
            }))}
        </Card> : <Card key={"card-base"}/>;
        const show_dangerous_chunks = (() => {
            if (dangerous_chunks === null || dangerous_chunks.size < 1) return "Not found!";
            return Array.from(dangerous_chunks).join(", ");
        })();
        return (
            <Space direction="vertical" style={{ width:"90%" }}>
                <br/>
                <br/>
                <Row justify={'center'}>
                    <Col lg={6} md={6} sm={4} xs={2}/>
                    <Col lg={8} md={9} sm={12} xs={15}>
                        <Input
                            prefix={<LockOutlined style={{color: 'rgba(0,0,0,.25)'}}/>}
                            placeholder="Password"
                            onChange={this.handlePasswordChange.bind(this)}
                            type={this.state.plain_text?"text":"password"}
                            suffix={this.state.plain_text? 
                            <div onClick={this.handleVisiableChange.bind(this)}><EyeTwoTone /></div> : 
                            <div onClick={this.handleVisiableChange.bind(this)}><EyeInvisibleOutlined /></div>}
                            // onBlur={this.handlePasswordValidation.bind(this)}
                        />

                    </Col>
                    <Col lg={4} md={3} sm={4} xs={5}>
                        <Button disabled={this.state["disable_btn"]}
                                loading={this.state["disable_btn"]}
                                type="primary" htmlType="submit" block
                                onClick={this.handleSubmit.bind(this)}
                                icon={<SecurityScanOutlined/>}
                        >
                            Check
                        </Button>
                    </Col>
                    <Col lg={6} md={6} sm={4} xs={2}/>
                </Row>
                <Row>
                    <Col lg={6} md={6} sm={4} xs={2}/>
                    <Col lg={12} md={12} sm={16} xs={20}>
                        {cards}
                    </Col>
                    <Col lg={6} md={6} sm={4} xs={2}/>
                </Row>
                <Row>
                    <Col lg={6} md={6} sm={4} xs={2}/>
                    <Col lg={12} md={12} sm={16} xs={20}>
                        <Descriptions column={3} size={"small"} bordered>
                            <Descriptions.Item label={"Score"}>
                                <Progress size={"small"} percent={progress} strokeColor={color} steps={6}
                                          showInfo={false}/>{score}
                            </Descriptions.Item>
                            <Descriptions.Item label={"Guesses"}>{show_gn}</Descriptions.Item>
                            <Descriptions.Item label={"Probability"}>{show_prob}</Descriptions.Item>
                            <Descriptions.Item label={"Dangerous chunks"}
                                               span={3}>
                                {show_dangerous_chunks}</Descriptions.Item>
                        </Descriptions>
                    </Col>
                    <Col lg={6} md={6} sm={4} xs={2}/>
                </Row>
            </Space>
        );
    }
}

load_model();

load_ranks();
